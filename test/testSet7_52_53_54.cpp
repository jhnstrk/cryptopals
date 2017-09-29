#include "testSet7_52_53_54.h"

#include <bitsnbytes.h>
#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet7_52_53_54)


// Note: The AES-128 based hash below is crap.
// -> Firstly its state is ridiculously small (16-bits).
// -> Secondly, for some input (e.g. repeated text), the output is statistically
//    very non-random. Certain hashes are far more common.

namespace {
    QByteArray H0() {
        QByteArray ret;
        ret.resize(2);
        ret[0] = (char)0x31;
        ret[1] = (char)0x41;
        return ret;
    }

    class MdHashBase {
    public:
        static const int BlockSizeBytes = qossl::AesBlockSize;
        // The final padding block, assuming the rest of the data is block-aligned.
        static QByteArray finalBlock(int count) {
            QByteArray block;
            block.append((char)0x80);
            block.append( QByteArray((BlockSizeBytes - 8) - block.size(),'\0'));

            // Message length in bits
            block.append( qossl::uint64Le(count * CHAR_BIT) );
            return block;
        }
    protected:
        MdHashBase() : m_count(0) {}
        virtual ~MdHashBase() {}

        QByteArray finalize()
        {
            m_buffer.append((char)0x80);
            if (m_buffer.size() <= (BlockSizeBytes - 8) ) {
                m_buffer.append( QByteArray((BlockSizeBytes - 8) - m_buffer.size(),'\0'));
            } else {
                m_buffer.append( QByteArray(BlockSizeBytes - m_buffer.size(),'\0'));
                this->addBlock(m_buffer,0);
                m_buffer = QByteArray((BlockSizeBytes - 8),'\0');
            }

            // Message length in bits
            m_buffer.append( qossl::uint64Le(m_count * CHAR_BIT) );

            this->addBlock(m_buffer,0);

            return m_state;
        }

        void addData(const QByteArray & data)
        {
            m_count += data.size();

            // less then a block
            if (m_buffer.size() + data.size() < BlockSizeBytes) {
                m_buffer.append(data);
                return;
            }

            int dataIndex = 0;
            if (!m_buffer.isEmpty()) {
                // fill buffer
                dataIndex = BlockSizeBytes - m_buffer.size();
                m_buffer.append(data.mid(0,dataIndex));
                this->addBlock(m_buffer,0);
            }

            int end = dataIndex + BlockSizeBytes;
            while (end <= data.size()) {
                this->addBlock(data, dataIndex);
                dataIndex = end;
                end += BlockSizeBytes;
            }

            m_buffer = data.mid(dataIndex);
        }

        virtual void addBlock(const QByteArray &data, int offset) = 0;

        QByteArray state() const { return m_state; }
    protected:
        QByteArray m_state;
        int m_count;
    private:
        QByteArray m_buffer;
    };

    // f
    class MdHash16 : public MdHashBase {
    public:
        MdHash16() {
            this->reset();
        }

        void reset() {
            m_state = H0();
            m_count = 0;
        }

        static QByteArray hash(const QByteArray & data)
        {
            MdHash16 hasher;
            hasher.addData(data);
            return hasher.finalize();
        }

        void addBlock(const QByteArray &data, int offset) Q_DECL_OVERRIDE
        {
            this->m_state = MdHash16::iteration(data.mid(offset,BlockSizeBytes), this->m_state);
        }

        static QByteArray iteration(const QByteArray & block, const QByteArray & hIn)
        {
            QByteArray padKey = QByteArray(BlockSizeBytes, (char)0);
            padKey[0] = hIn.at(0);
            padKey[1] = hIn.at(1);

            QByteArray eblock = qossl::aesEcbEncrypt(block, padKey);
            eblock.resize(2);
            return eblock;
        }

    };


    // g : 24-bit version.
    class MdHash24 : public MdHashBase {
    public:
        MdHash24() {
            this->reset();
        }

        void reset() {
            m_state.resize(3);
            m_state[0] = (char)0x31;
            m_state[1] = (char)0x41;
            m_state[2] = (char)0x59;  // Digits of Pi.
            m_count = 0;
        }

        static QByteArray hash(const QByteArray & data)
        {
            MdHash24 hasher;
            hasher.addData(data);
            return hasher.finalize();
        }

        void addBlock(const QByteArray &data, int offset) Q_DECL_OVERRIDE
        {
            this->m_state = MdHash16::iteration( data.mid(offset,BlockSizeBytes), this->m_state);
        }

        static QByteArray iteration(const QByteArray & block, const QByteArray & hIn)
        {
            QByteArray padKey = QByteArray(BlockSizeBytes, (char)0);
            padKey[0] = hIn.at(0);
            padKey[1] = hIn.at(1);
            padKey[2] = hIn.at(2);

            QByteArray eblock = qossl::aesEcbEncrypt(block, padKey);
            eblock.resize(3);
            return eblock;
        }
        private:
    };

    class CollisionFinder {

    public:
        CollisionFinder() : m_cfCount(0)
        {}

    struct Collision {
        Collision() {}
        Collision( const QByteArray& hi, const QByteArray & ho,
                   const QByteArray & col1,const QByteArray & col2 ):
            hIn(hi), // Input state
            hOut(ho), // output state
            c1(col1),
            c2(col2)
        {}

        QByteArray hIn;
        QByteArray hOut;
        QByteArray c1;
        QByteArray c2;
    };

    Collision findCollision(const QByteArray& hIn)
    {
        ++m_cfCount;

        QHash< QByteArray ,QByteArray > tested;
        while(true) {
            QByteArray sample = qossl::randomBytes(qossl::AesBlockSize);

            QByteArray hOut = MdHash16::iteration(sample,hIn);
            if (tested.contains(hOut)) {
                if (tested.value(hOut) != sample) {
                    return Collision(hIn, hOut, tested.value(hOut), sample );
                }
            } else {
                tested[hOut] = sample;
            }
        }
    }

    void find2nCollisions(int n)
    {
        QByteArray h;
        if (m_collisions.isEmpty()) {
            h = H0();
        } else {
            h = m_collisions.back().hOut;
        }

        for (int i=0; i<n; ++i) {
            Collision nextC = findCollision(h);
            m_collisions.append(nextC);
            h = nextC.hOut;
            qDebug() << "Collision" << nextC.hIn.toHex() << nextC.hOut.toHex()
                     << nextC.c1.toHex() << nextC.c2.toHex();
        }
        return;
    }

    QByteArray hOut(int nMax = -1) const {
        if (m_collisions.isEmpty()) {
            return H0();
        }
        if (nMax == -1) {
            nMax = m_collisions.size() - 1;
        } else {
            nMax = std::min(nMax, m_collisions.size()-1);
        }
        return m_collisions.at(nMax).hOut;
    }

    int nMax() const { return m_collisions.size(); }

    QByteArray makeCollision(unsigned int n, int nMax = -1) const
    {
        QByteArray total;
        if (nMax == -1) {
            nMax = m_collisions.size();
        } else {
            nMax = std::min(nMax, m_collisions.size());
        }

        for (int i=0; i<nMax; ++i) {
            if ((n & (1<<i)) == 0) {
                total += m_collisions.at(i).c1;
            } else {
                total += m_collisions.at(i).c2;
            }
        }
        return total;
    }

    unsigned int cfCount() const { return m_cfCount; }
    private:
            QList<Collision> m_collisions;
            unsigned int m_cfCount; // number of calls
    };

}

void TestSet7_52_53_54::testChallenge52()
{
    CollisionFinder cf;

    unsigned int n = 4;
    cf.find2nCollisions(n);

    // print all 2^4 collisions.
    QByteArray cValue;
    for (unsigned int i=0; i< (1<<n); ++i)
    {
        const QByteArray data = cf.makeCollision(i);
        const QByteArray h = MdHash16::hash(data);
        qDebug() << i << h.toHex();
        if (i == 0) {
            cValue = h;
        } else {
            QCOMPARE(h, cValue);  // Ensure collision, including padding matches.
        }
    }

    qDebug() << "Found 2^4 collisions";

    // Keep increasing the number of messages in the pool until we hit a collision.
    bool haveCollision =false;
    while(!haveCollision && (n < 24)) {

        // Find more 2^4 times more collisions.
        cf.find2nCollisions(4);
        QHash < QByteArray, unsigned int > gHashes;

        n = cf.nMax();

        // See if there's a match in g.
        for (unsigned int i=0; i< (1<<n); ++i)
        {
            QByteArray data = cf.makeCollision(i);
            QByteArray h = MdHash24::hash(data);
            if (gHashes.contains(h)) {
                qDebug() << "Collision in g found";
                haveCollision = true;

                QByteArray g1 = cf.makeCollision(gHashes.value(h));
                QByteArray g2 = data;
                qDebug() << "g1:" << g1.toHex();
                qDebug() << "g2:" << g2.toHex();

                // Confirm it collides for both functions:
                QCOMPARE(MdHash24::hash(g1), MdHash24::hash(g2));
                QCOMPARE(MdHash16::hash(g1), MdHash16::hash(g2));
                break;
            }
            gHashes[h] = i;
        }
    }

    QVERIFY(haveCollision);

    qDebug() << "Collision function called: " << cf.cfCount() << "times";
}




namespace Challenge53 {

class CollisionFinder2 {

public:
    CollisionFinder2() : m_cfCount(0), m_padChar(0)
    {}

    struct Collision2 {
        Collision2() : padLenBlocks(0){}
        Collision2(const QByteArray & hIn_, const QByteArray & hOut_,
                   const QByteArray & input1_,int numPadBlocks, const QByteArray & input2_ )
                   :
            hIn(hIn_),
            hOut(hOut_),
            input1(input1_),
            padLenBlocks(numPadBlocks),
            input2(input2_)
        {}

        QByteArray hIn;
        QByteArray hOut;
        QByteArray input1;
        int padLenBlocks;
        QByteArray input2;
    };



    Collision2 findCollision2(const QByteArray& hIn, const int numPadBlock)
    {
        ++m_cfCount;

        // Hash dummy blocks.
        const QByteArray hIn2 = dummyState(numPadBlock, hIn);

        QHash< QByteArray ,QByteArray > tested1;
        QHash< QByteArray ,QByteArray > tested2;
        while(true) {
            QByteArray sample = qossl::randomBytes(qossl::AesBlockSize);

            const QByteArray hOut1 = MdHash16::iteration(sample,hIn);
            if (tested2.contains(hOut1)) {
                return Collision2(hIn, hOut1, sample, numPadBlock, tested2.value(hOut1));
            } else {
                tested1[hOut1] = sample;
            }

            const QByteArray hOut2 = MdHash16::iteration(sample,hIn2);
            if (tested1.contains(hOut2)) {
                return Collision2(hIn, hOut2, tested1.value(hOut2), numPadBlock, sample);
            } else {
                tested2[hOut2] = sample;
            }
        }
    }

    // Hashing dummy blocks
    QByteArray dummyState(int blockCount, QByteArray h)
    {
        QByteArray padding(MdHash16::BlockSizeBytes, m_padChar);

        for (int i=0; i<blockCount; ++i) {
            h = MdHash16::iteration(padding,h);
        }
        return h;
    }

    QVector<Collision2> prepare2kCollisions(int k) {
        QVector<Collision2> ret;

        QByteArray h1 = H0();
        for (int n = 1; n<=k; ++n) {

            const int twokmn = (1 << (k-n)); // 2^(k-n)

            // Collision between short and long blocks.
            Collision2 x = findCollision2(h1,twokmn);

            ret.append(x);

            h1 = x.hOut;
        }
        return ret;
    }

    QByteArray makeLongBlock(const Collision2 & c)
    {
        QByteArray ret(c.padLenBlocks * MdHash16::BlockSizeBytes, m_padChar);
        ret.append(c.input2);
        return ret;
    }
private:
    int m_cfCount;
    const char m_padChar;
};

}

void TestSet7_52_53_54::testChallenge53()
{
    using namespace Challenge53;
    CollisionFinder2 finder;

    const int k = 16;
    const QVector<CollisionFinder2::Collision2> vec = finder.prepare2kCollisions(k);
    const int twopk = (1 << k);

    for (int i=0; i<vec.size(); ++i) {
        CollisionFinder2::Collision2 c = vec.at(i);

        qDebug() << "Collision" << i << c.hIn.toHex() << c.hOut.toHex();
    }

    const QByteArray longMessage = qossl::randomBytes(65536 * 16);

    QMap< QByteArray, QList< int > > messageMap;
    int dataIndex = 0;
    int end = dataIndex + MdHash16::BlockSizeBytes;
    QByteArray state = H0();
    messageMap[state].push_back(0);
    while (end <= longMessage.size()) {
        state = MdHash16::iteration(longMessage.mid(dataIndex,MdHash16::BlockSizeBytes), state);
        messageMap[state].push_back(end);
        dataIndex = end;
        end += MdHash16::BlockSizeBytes;
    }

    qDebug() << vec.back().hOut.toHex();
    if (! messageMap.contains(vec.back().hOut)) {
        qDebug() << "Not long enough!";
        return;
    }

    // Get the byte offset of the last match
    const CollisionFinder2::Collision2 & lastC( vec.back() );
    const int iBridge = messageMap.value(lastC.hOut).back();
    const int iBlock = iBridge / MdHash16::BlockSizeBytes;
    QVERIFY( iBridge % MdHash16::BlockSizeBytes == 0);

    if (iBlock < k) {
        qDebug() << "Cannot bridge, block too small";
        return;
    }

    if (iBlock > k + twopk - 1) {
        qDebug() << "Cannot bridge, block too big";
        return;
    }

    QByteArray forged;
    // Build the bridge...
    const int numExtra = iBlock - k;
    for (int i=0; i<k; ++i) {
        if ((numExtra & (1 << (k-i-1))) != 0 ) {
            // Long block
            forged.append(finder.makeLongBlock(vec.at(i)));
        } else {
            // Short block
            forged.append(vec.at(i).input1);
        }
    }

    QCOMPARE(forged.length(), iBridge);

    forged.append(longMessage.mid(iBridge));

    QCOMPARE(forged.length(), longMessage.length());

    QCOMPARE(MdHash16::hash(forged).toHex(), MdHash16::hash(longMessage).toHex());

    qDebug() << "Original hash:" << MdHash16::hash(longMessage).toHex();
    qDebug() << "Forgery hash:" << MdHash16::hash(forged).toHex();

    QVERIFY(forged != longMessage);
}


//=============================================================================
namespace Challenge54 {

    class CollisionTree{
    public:
        struct CollisionTreeNode {
            CollisionTreeNode() {}
            CollisionTreeNode(const QByteArray& hOut_,const QByteArray & col1, const QByteArray & col2) :
                hOut(hOut_),
                block1(col1),
                block2(col2)
            {}

            QByteArray hOut;
            QByteArray block1;
            QByteArray block2;
        };

        CollisionTree() {}

        void buildTree(int k){
            // Grow the tree...
            const int twopk = (1 << k);
            addLeaves(twopk);
            buildLayer0();
            while(m_treeLayers.back().size() > 1) {
                buildNextLayer();
            }
        }

        bool isLeaf(const QByteArray & h) const
        {
            return m_leafMap.contains(h);
        }

        QByteArray outputState() const {
            return this->m_treeLayers.back().back().hOut;
        }

        QByteArray padding(const QByteArray& hIn) const
        {
            int i = m_leafMap.value(hIn,-1);
            if (i == -1) {
                qWarning() << "Initial state is not a leaf of the tree";
                return QByteArray();
            }
            QByteArray ret;
            for (int j=0; j<m_treeLayers.size(); ++j)
            {
                const int iNext = i/2;
                const CollisionTreeNode & node(m_treeLayers.at(j).at(iNext));
                if ((i & 1) == 0) {
                    ret.append(node.block1);
                } else {
                    ret.append(node.block2);
                }
                i = iNext;
            }
            return ret;
        }

        QByteArray leaf(int i) const {
            return m_leaves.at(i);
        }
    private:
        void addLeaves(const int n)
        {
            while (m_leaves.size() < n) {
                QByteArray next = randomH();
                if (!m_leaves.contains(next)) {
                    m_leafMap[next] = m_leaves.size();
                    m_leaves.push_back(next);
                }
            }
        }

        // Pair up hashes in current top layer to build next.
        void buildLayer0(){
            QList< CollisionTreeNode > layer0;
            for (int i=0; i< this->m_leaves.size(); i+=2) {
                const QByteArray h1 = m_leaves.at(i);
                const QByteArray h2 = (i+1 < m_leaves.size()) ? m_leaves.at(i+1) : h1;
                const CollisionTreeNode node = this->findCollision(h1,h2);
                layer0.push_back(node);
            }
            m_treeLayers.clear();
            m_treeLayers.push_back(layer0);
        }

        void buildNextLayer()
        {
            QList< CollisionTreeNode > layer;
            QList< CollisionTreeNode > & pLayer( m_treeLayers.back() );
            for (int i=0; i< pLayer.size(); i+=2) {
                const QByteArray h1 = pLayer.at(i).hOut;
                const QByteArray h2 = (i+1 < pLayer.size()) ? pLayer.at(i+1).hOut : h1;
                const CollisionTreeNode node = this->findCollision(h1,h2);
                layer.push_back(node);
            }
            m_treeLayers.push_back(layer);
        }

        // Given 2 input states find 2 blocks that make a collision.
        CollisionTreeNode findCollision(const QByteArray& hIn1, const QByteArray& hIn2)
        {
            QHash< QByteArray ,QByteArray > tested1;
            QHash< QByteArray ,QByteArray > tested2;
            while(true) {
                QByteArray sample = qossl::randomBytes(qossl::AesBlockSize);

                const QByteArray hOut1 = MdHash16::iteration(sample,hIn1);
                if (tested2.contains(hOut1)) {
                    return CollisionTreeNode(hOut1, sample, tested2.value(hOut1));
                } else {
                    tested1[hOut1] = sample;
                }

                const QByteArray hOut2 = MdHash16::iteration(sample,hIn2);
                if (tested1.contains(hOut2)) {
                    return CollisionTreeNode(hOut2, tested1.value(hOut2), sample);
                } else {
                    tested2[hOut2] = sample;
                }
            }
        }

        // Get a new random input state
        QByteArray randomH() const
        {
            return qossl::randomBytes(m_stateLen);
        }

        static const int m_stateLen = 2;

        QMap< QByteArray, int > m_leafMap;  // Input states
        QList< QByteArray > m_leaves;
        QList< QList< CollisionTreeNode > > m_treeLayers;
    };
}
void TestSet7_52_53_54::testChallenge54()
{
    const int k = 12;

    using namespace Challenge54;

    qDebug() << "Building collision tree";
    CollisionTree tree;
    tree.buildTree(k);

    const int expectedPaddingSize = k * MdHash16::BlockSizeBytes;

    for (int i=0; i<100; ++i) {
        const QByteArray leaf = tree.leaf(i);
        QVERIFY(tree.isLeaf(leaf));
        const QByteArray padding = tree.padding(leaf);
        QCOMPARE(padding.size(), expectedPaddingSize);
    }

    // Make my prediction...
    const int count =
            (120000/MdHash16::BlockSizeBytes) * MdHash16::BlockSizeBytes  // Content, rounded to block.
            + MdHash16::BlockSizeBytes  // Glue block.
            + expectedPaddingSize;      // Traversing the tree
    const QByteArray hOut = tree.outputState();
    const QByteArray finalBlock = MdHashBase::finalBlock(count);
    const QByteArray prediction = MdHash16::iteration(finalBlock,hOut);

    qDebug() << "Expected message length:" << count;
    qDebug() << "My prediction has the following hash:" << prediction.toHex();

    // Now the real results come in...
    QFile file(":/qossl_test_resources/rsc/set7/mlb_2016.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray actual = QByteArray::fromBase64(file.readAll());
    file.close();

    // Pad to the correct size, minus one block.
    int glueLen = count - actual.size() - expectedPaddingSize - MdHash16::BlockSizeBytes;
    const QByteArray glue1 = QByteArray(glueLen, ' ');
    // Hash the actual results + the glue.
    const QByteArray leadingBit( actual + glue1 );
    QCOMPARE(leadingBit.size() % MdHash16::BlockSizeBytes, 0);

    // Compute the intermediate hash.
    QByteArray h = H0();
    for (int i=0; i<leadingBit.size(); i+=MdHash16::BlockSizeBytes) {
        h = MdHash16::iteration(leadingBit.mid(i,MdHash16::BlockSizeBytes),h);
    }

    // Find a glue block to attach to the tree.
    const QByteArray hGlue = h; // Intermediate hash.

    QByteArray block = QByteArray(MdHash16::BlockSizeBytes, ' ');
    while(true) {
        QByteArray testH = MdHash16::iteration(block,h);
        if (tree.isLeaf(testH)) {
            h = testH;
            break;
        }
        block = qossl::randomBytes(MdHash16::BlockSizeBytes/2).toHex();
    }

    const QByteArray theRest = block + tree.padding(h);

    const QByteArray proof = actual + glue1 + theRest;

    qDebug() << "Actual message size:" << proof.size();

    QCOMPARE(proof.size(), count);

    qDebug() << "The hash of the results data is:" << MdHash16::hash(proof).toHex();

    // Verify that the 'proof' message has the correct hash.
    QCOMPARE( MdHash16::hash(proof).toHex(), prediction.toHex());

}

