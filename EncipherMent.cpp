#include"EncipherMent.h"
extern "C"
{
#include <openssl/applink.c>
};
RsaEncipherMent::RsaEncipherMent()
{

}

QByteArray RsaEncipherMent::BioEncrypt(const QByteArray &PlainData, const QByteArray &Pubkey, bool pkcs1 /*= false*/)
{
    BIO* pKeyBio = BIO_new_mem_buf(Pubkey.data(), Pubkey.size());
    if (pKeyBio == NULL)
    {
        return "";
    }
    RSA* pRsa = RSA_new();
    if (pkcs1)
    {
        //pkcs#1
        pRsa = PEM_read_bio_RSAPublicKey(pKeyBio, &pRsa, NULL, NULL);

    }
    else
    {
        //pkcs#8
        pRsa = PEM_read_bio_RSA_PUBKEY(pKeyBio, &pRsa, NULL, NULL);

    }
    if (pRsa == NULL)
    {
        BIO_free_all(pKeyBio);
        return "";
    }

    int nLen = RSA_size(pRsa);
    QByteArray strEncryptData = "";
    strEncryptData.resize(nLen); // 调整输出buf大小
    //加密
    int nSize = RSA_public_encrypt(PlainData.size(),
        (uchar*)PlainData.data(),
        (uchar*)strEncryptData.data(),
        pRsa,
        RSA_PKCS1_PADDING);
    //释放内存
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strEncryptData.toBase64();
}

QByteArray RsaEncipherMent::BioDecrypt(const QByteArray &PlainData, const QByteArray &Prikey)
{
    BIO* pKeyBio = BIO_new_mem_buf(Prikey.data(), Prikey.size());
    if (pKeyBio == NULL)
    {
        return "";
    }
    RSA* pRsa = RSA_new();
    pRsa = PEM_read_bio_RSAPrivateKey(pKeyBio, &pRsa, NULL, NULL);
    if (pRsa == NULL)
    {
        BIO_free_all(pKeyBio);
        return "";
    }
    int nLen = RSA_size(pRsa);
   QByteArray strEncryptData = "";
   strEncryptData.resize(nLen);
    //解密
    int nSize = RSA_private_decrypt(PlainData.size(),
        (uchar*)PlainData.data(),
        (uchar*)strEncryptData.data(),
        pRsa,
        RSA_PKCS1_PADDING);


    //释放内存
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strEncryptData.mid(0,nSize);
}

QByteArray RsaEncipherMent::FileEncrypt(const QByteArray &PlainData, const QByteArray &pem_path,bool pkcs1)
{
    RSA * rsa = NULL;
    FILE* fp = NULL;
    char* en = NULL;
    if((fp = fopen((char*)pem_path.data(),"rb")) == NULL)
    {
        return "";
    }
    if(pkcs1)
    {
        if((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL)
        {
            return "";
        }
    }
    else
    {
        if((rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL)
        {
            return "";
        }

    }
    int rsa_len = RSA_size(rsa);
    QByteArray encode;
    encode.resize(rsa_len);
    int reasult = RSA_public_encrypt(PlainData.size(), (unsigned char*)PlainData.data(), (unsigned char*)encode.data(), rsa, RSA_PKCS1_PADDING);
    if(reasult == -1)
    {
        return "";
    }
    RSA_free(rsa);
    return encode.toBase64();

}

QByteArray RsaEncipherMent::FileDecrypt(const QByteArray &PlainData, const QByteArray &pem_path)
{
    RSA *rsa = NULL;
    FILE*fp = NULL;
    char*de = NULL;
    int rsa_len = 0;
    if((fp = fopen(pem_path.data(),"rb")) == NULL)
    {
        return "read fail";
    }
    if((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL)
    {
        return NULL;
    }
    rsa_len = RSA_size(rsa);
    QByteArray decode;
    decode.resize(rsa_len);
    int reasult = RSA_private_decrypt(PlainData.size(), (unsigned char*)PlainData.data(), (unsigned char*)decode.data(), rsa, RSA_PKCS1_PADDING);
    if( reasult==-1)
    {
        return "";
    }
    RSA_free(rsa);
    fclose(fp);
    return decode.mid(0,reasult);

}
