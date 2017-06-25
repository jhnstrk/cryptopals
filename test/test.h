#ifndef TEST_H__
#define TEST_H__

#include <QString>

class QObject;

class RegisterTestBase {
public:
    RegisterTestBase(const QString & name);
    virtual ~RegisterTestBase() {}

    QString name() const { return m_name; }
    virtual QObject * create() = 0;

    static void AppendTest( const QString & name, RegisterTestBase * obj);
protected:
    QString m_name;
};

template < class T > class RegisterTest : public RegisterTestBase
{
public:
    typedef T TestClass;
    RegisterTest( const QString & name): RegisterTestBase(name)
    {}

    QObject * create() { return new TestClass(); }
};

#define JDS_ADD_TEST(TestName) namespace {   RegisterTest<TestName> theTest = RegisterTest<TestName>( # TestName );  }

#endif
