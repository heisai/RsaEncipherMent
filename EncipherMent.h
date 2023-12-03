#ifndef ENCIPHERMENT_H
#define ENCIPHERMENT_H
#include<QObject>
#include"openssl/rsa.h"
#include"openssl/pem.h"

class RsaEncipherMent
{
public:
    explicit RsaEncipherMent();
     //密钥 以内存的形式存储
    QByteArray BioEncrypt(const QByteArray &PlainData, const QByteArray &Pubkey,bool pkcs1 = false);
    QByteArray BioDecrypt(const QByteArray &PlainData, const QByteArray &Prikey);

    //密钥 以文件的形式存储
    QByteArray FileEncrypt(const QByteArray &PlainData, const QByteArray &pem_path,bool pkcs1 = false);
    QByteArray FileDecrypt(const QByteArray &PlainData, const QByteArray &pem_path);


    //内存形式 pkcs8
    const QString public_key = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALmxDatSZ6vOkzQfXRUlJoR8mbiGOM7FxRX8WolGY3z/tT2CxLE0TFLDz2DcGMKBo68MNfkpCF0+IsH9DimfHFMCAwEAAQ==\n-----END PUBLIC KEY-----\n";
    const QString private_key = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAubENq1Jnq86TNB9d FSUmhHyZuIY4zsXFFfxaiUZjfP+1PYLEsTRMUsPPYNwYwoGjrww1+SkIXT4iwf0OKZ8cUwIDAQABAkAoTg7qfdN0zjzTVm9s1Ih8v1LaY3/XGcRClmjMXRPhIHynq98B/03mBZ+OXDSGjOtvlLD2Tv70HmwBEHigMn3xAiEA7Vr603otCwBOfy8Pa1/gQqQSWBMLP4oUVw6Rwz6qcUsCIQDIRyhsNI6lBEpF9G+QxneE/agG6bLKaA82cn9K1XKkGQIhAJRTpamgkSNt1qAeTZmBOckLdTc6922GoX1h6m9D6wmPAiEAucDFzRYx9vszqA4+K5jn4YEiBsdZ/EDnWyh2x4GRAoECIAY4wKOCodXaL3W76zaqaiF4xlkOh2/vAMoVirqRNdGA\n-----END PRIVATE KEY-----\n";

    //内存形式 pkcs1
    const QString public_keypkcs1 = "-----BEGIN RSA PUBLIC KEY-----\nMEgCQQDBTs84K32azWD5PWx44QulreGUwZc1b4iOkwV8EBTw9w9P7vbfA0VN5W27A7ebhEJa287hm1hH/24mE1X5EWUxAgMBAAE=\n-----END RSA PUBLIC KEY-----\n";
    const QString private_keypkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAMFOzzgrfZrNYPk9bHjhC6Wt4ZTBlzVviI6TBXwQFPD3D0/u9t8DRU3lbbsDt5uEQlrbzuGbWEf/biYTVfkRZTECAwEAAQJAK3WaZNhyPrFZ0e8bSfnecnsrMhRr+FmA6/zlyMSc0Kd1/LzlTrCp90vJrEUbLio8+BBBBu5QvqCJDCatNRvYAQIhAPwS5bJTp821w6MWz6CTdn+2NNl/6OuOEU7vFMhojnrBAiEAxFGXtJWKFvTZHQgYTMRWQ1DHvj+MsTxtYWabJUjotnECIQCwCl6B+KxjHIKhfkfIY9PJAy3Li+nV v+TUlGGWSHbgwQIhAME+B3SMVjcuoKBBHZpDER6F33fXmifD8W8Uztauo9MhAiA0r1z3wnJNvyQuxduIhh6G9cCX6RoFXW9cKA3mIy/yHA==\n-----END RSA PRIVATE KEY-----\n";
};
#endif // ENCIPHERMENT_H
