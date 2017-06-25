#include "test.h"

#include <QMap>
#include <QObject>
#include <QString>

#include <QTest>
#include <QScopedPointer>

#include <iostream>


QMap< QString, RegisterTestBase *> & getTestObjs()
{
    static QMap< QString, RegisterTestBase *> TestObjs;
    return TestObjs;
}

RegisterTestBase::RegisterTestBase(const QString & name): m_name(name)
{
    AppendTest(name, this);
}

//static
void RegisterTestBase::AppendTest(const QString & name, RegisterTestBase *obj)
{
    getTestObjs()[name] = obj;
}

int main(int argc, char * argv[])
{
    QMap< QString, RegisterTestBase *>& TestObjs( getTestObjs() );

    QCoreApplication app(argc, argv);
    QStringList testNames;

    if (app.arguments().size() >= 2) {
        testNames = app.arguments().mid(1);
        if (testNames.at(0) == "ALL") {
            testNames = TestObjs.keys();
        }
    } else {
        const QStringList keys = TestObjs.keys();
        for (int i=0; i<keys.size(); ++i)
        {
            std::cout << i << " " << keys.at(i).toLocal8Bit().constData() << std::endl;
        }
        std::cout << "Enter test id or name (-1 for all):" << std::flush;
        std::string indexStr;
        std::cin >> indexStr;

        QString qstr(QString::fromStdString(indexStr));
        if (TestObjs.contains(qstr)) {
            testNames << qstr;
        } else {
            bool ok = false;
            int index = qstr.toInt(&ok);
            if (!ok || index <-1 || index >= keys.size()) {
              std::cerr << "Invalid index" << std::endl;
            }
            if (index == -1) {
                testNames = keys;
            } else {
                testNames << keys.at(index);
            }
        }
    }

    //app.setAttribute(Qt::AA_Use96Dpi, true);

    int ret = 0;

    foreach (const QString & testName, testNames) {
        RegisterTestBase * ptr = TestObjs.value(testName, Q_NULLPTR);
        if (!ptr) {
            std::cerr << "Unknown test " << testName.toLocal8Bit().constData() << std::endl;
            return 1;
        }
        QScopedPointer<QObject>  testObject(ptr->create());
        ret += QTest::qExec(testObject.data(), 1, argv);
    }

    return ret;
}
