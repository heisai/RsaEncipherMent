#include <QCoreApplication>
#include"EncipherMent.h"
#include<QDebug>
#include<QDir>
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    RsaEncipherMent Rsatest;
#if 0
    QByteArray data = Rsatest.BioEncrypt("1234567",Rsatest.public_key.toUtf8());
    qDebug()<<data;
    data = Rsatest.BioDecrypt(QByteArray::fromBase64(data),Rsatest.private_key.toUtf8());
    qDebug()<<data;
#endif
#if 0
    QByteArray data = Rsatest.BioEncrypt("1234567",Rsatest.public_keypkcs1.toUtf8(),true);
    qDebug()<<data;
    data = Rsatest.BioDecrypt(QByteArray::fromBase64(data),Rsatest.private_keypkcs1.toUtf8());
    qDebug()<<data;
#endif
#if 0
    QString public_key = QString("%1/%2").arg(QDir::currentPath()).arg("pemfile/public_key.pem");
    QString private_key = QString("%1/%2").arg(QDir::currentPath()).arg("pemfile/private_key.pem");
    qDebug()<< public_key << private_key;
    QByteArray data = Rsatest.FileEncrypt("1234567",public_key.toUtf8());
    qDebug()<<data;
    data = Rsatest.FileDecrypt(QByteArray::fromBase64(data),private_key.toUtf8());
    qDebug()<<data;
#endif

    QString public_key = QString("%1/%2").arg(QDir::currentPath()).arg("pemfile/public_key_cs1.pem");
    QString private_key = QString("%1/%2").arg(QDir::currentPath()).arg("pemfile/private_key_cs1.pem");
    qDebug()<< public_key << private_key;
    QByteArray data = Rsatest.FileEncrypt("1234567",public_key.toUtf8(),true);
    qDebug()<<data;
    data = Rsatest.FileDecrypt(QByteArray::fromBase64(data),private_key.toUtf8());
    qDebug()<<data;
    return a.exec();
}
