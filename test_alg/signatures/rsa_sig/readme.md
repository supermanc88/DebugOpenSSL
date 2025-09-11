# RSA

## RSA 结构
RSA 是一种非对称加密算法，由 Ron Rivest、Adi Shamir 和 Leonard Adleman 在 1977 年提出。RSA 算法基于大数分解的数学难题，其安全性依赖于大整数分解的计算复杂性。RSA 算法广泛应用于数据加密和数字签名。
RSA 算法的核心思想是使用一对密钥：公钥和私钥。公钥用于加密数据，私钥用于解密数据。公钥可以公开分发，而私钥必须保密。

PKCS#1 中描述了 RSA 结构：

```asn1
RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
```

```asn1
RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1           INTEGER,  -- p
    prime2           INTEGER,  -- q
    exponent1        INTEGER,  -- d mod (p-1)
    exponent2        INTEGER,  -- d mod (q-1)
    coefficient      INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos  OtherPrimeInfos OPTIONAL
}
```

## 填充模式详解
OpenSSL 支持三种主要的 RSA 填充模式：

- RSA_PKCS1_PADDING：

带摘要：先哈希消息，再应用PKCS#1 v1.5填充

不带摘要：直接对原始数据应用PKCS#1 v1.5填充

- RSA_PKCS1_PSS_PADDING：

必须带摘要：PSS填充方案，更安全

支持可配置的盐长度

- RSA_NO_PADDING：

不带摘要：直接RSA数学运算

输入数据长度必须等于RSA模长
