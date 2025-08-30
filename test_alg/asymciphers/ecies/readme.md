# ECIES



ECIES是一种混合加密方案，它巧妙地结合了非对称加密（椭圆曲线密码学）和对称加密的优点。它使用非对称加密来安全地交换密钥，然后使用高效的对称加密来加密实际的消息数据。这使得它既安全又高效，非常适合加密长度可变的数据。

------

### **ECIES 加密流程 (Encryption)**

假设 Alice 想要加密一条消息发送给 Bob。Alice 需要知道 Bob 的公钥，而 Bob 必须保管好自己的私钥。

**前提条件：**

- **Alice (发送方)**：拥有 Bob 的公钥 ![img](images/readme/b59676b3246575fe91046496a22e2f44.svg)。
- **Bob (接收方)**：拥有自己的密钥对（私钥 ![img](images/readme/76463dc54843a62df77e170a160eaa85-20250830135142386.svg) 和公钥 ![img](images/readme/b59676b3246575fe91046496a22e2f44.svg)）。
- 双方协定一套**椭圆曲线域参数**（如 `secp256k1`）、一个**密钥派生函数 (KDF)**（如 HKDF）、一个**对称加密算法 (Cipher)**（如 AES-256-GCM）和一个**消息认证码算法 (MAC)**（如 HMAC-SHA-256）。

以下是 Alice 加密的详细步骤：

#### **第一步：生成临时（Ephemeral）密钥对**

Alice 首先需要为本次加密会话生成一个一次性的、临时的椭圆曲线密钥对。这个密钥对只用于这一次加密，之后就会被丢弃。

1. 生成一个随机的私钥（一个大整数） ![img](images/readme/72cb3a229067770aeb6caa625a65a1a1-20250830135142397.svg)。
2. 利用域参数中的生成点 ![img](images/readme/f8df64a4bfdeb9bdcbc357668b6fb123-20250830135142397.svg) 计算出对应的公钥 ![img](images/readme/bd2f9c198a94e67e0e895dca11bc2218.svg)。

这个临时公钥 ![img](images/readme/dd1caa3f2e1582dab2cf9bfdb21b7556-20250830135142392.svg) 将会是加密后数据的一部分，需要发送给 Bob。

#### **第二步：生成共享密钥 (Shared Secret)**

Alice 使用她刚刚生成的临时私钥 ![img](images/readme/72cb3a229067770aeb6caa625a65a1a1-20250830135142397.svg) 和 Bob 的公用公钥 ![img](images/readme/b59676b3246575fe91046496a22e2f44.svg) 来计算一个共享密钥点 ![img](images/readme/55fc237afbe535f7d8434985b848a6a7-20250830135142394.svg)。这是基于**椭圆曲线迪菲-赫尔曼密钥交换 (ECDH)** 协议的。

![img](images/readme/0dd2268c4321a9dedbd5ec54cb595675.svg)

由于 ![img](images/readme/fe35179533a6ae7dbd249a249db4c5a0.svg)，所以 ![img](images/readme/22583f8d59cab5d28aed1c1d49942b17.svg)。这个共享密钥点 ![img](images/readme/55fc237afbe535f7d8434985b848a6a7-20250830135142394.svg) 是一个椭圆曲线上的点，其坐标 `(Sx, Sy)` 只有 Alice 和 Bob 能够计算出来。通常只取其 x 坐标 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg) 作为共享密钥的基础。

#### **第三步：使用密钥派生函数 (KDF) 生成对称密钥**

直接使用共享密钥点 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg) 作为加密密钥是不安全的。Alice 需要使用一个密钥派生函数 (KDF) 从 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg) 中派生出实际用于加密和验证的对称密钥。

KDF 会将 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg) 作为输入，生成两个独立的密钥：

1. **加密密钥** ![img](images/readme/c85c3acab643ca1a8c0148a3c3a4cd33-20250830135142403.svg): 用于对称加密算法（如 AES）。
2. **认证密钥** ![img](images/readme/5f92fe34f5f3af5fbbd75d5b0e38b800-20250830135142406.svg): 用于消息认证码算法（如 HMAC）。

![img](images/readme/181ba6d1b763e3c48b832078d4141c17-20250830135142406.svg)

（注：`||` 表示拼接。KDF会输出一个足够长的密钥材料，然后按需切分成 ![img](images/readme/c85c3acab643ca1a8c0148a3c3a4cd33-20250830135142403.svg) 和 ![img](images/readme/5f92fe34f5f3af5fbbd75d5b0e38b800-20250830135142406.svg)）。

#### **第四步：使用对称加密算法加密消息**

Alice 使用上一步生成的加密密钥 ![img](images/readme/c85c3acab643ca1a8c0148a3c3a4cd33-20250830135142403.svg) 和对称加密算法（例如 AES）来加密她的原始消息 ![img](images/readme/4760e2f007e23d820825ba241c47ce3b-20250830135142411.svg)。

![img](images/readme/aa1619baa4a13df613cc1731b9505f0e-20250830135142413.svg)

这里的 ![img](images/readme/b891664b42113aee13f0bac25eb998e5-20250830135142412.svg) 就是加密后的密文。

#### **第五步：生成消息认证码 (MAC)**

为了防止密文在传输过程中被篡改，Alice 需要使用认证密钥 ![img](images/readme/5f92fe34f5f3af5fbbd75d5b0e38b800-20250830135142406.svg) 和 MAC 算法（例如 HMAC-SHA-256）来为刚刚生成的密文 ![img](images/readme/b891664b42113aee13f0bac25eb998e5-20250830135142412.svg) 计算一个标签（tag）。

![img](images/readme/81eb38bfc81a882ef56e0fa197e2f81f-20250830135142412.svg)

这个标签 ![img](images/readme/56c1b0cb7a48ccf9520b0adb3c8cb2e8-20250830135142417.svg) 是对密文完整性和真实性的一个“签名”。

#### **第六步：组合最终的加密数据**

最后，Alice 将本次加密过程中生成的几个部分组合在一起，形成最终要发送给 Bob 的加密数据包。

![img](images/readme/74e3d80b8663e809df4e8be05ace02bc-20250830135142419.svg)

- ![img](images/readme/dd1caa3f2e1582dab2cf9bfdb21b7556-20250830135142392.svg)：Alice 的临时公钥（一个点）。
- ![img](images/readme/b891664b42113aee13f0bac25eb998e5-20250830135142412.svg)：对称加密后的消息密文。
- ![img](images/readme/56c1b0cb7a48ccf9520b0adb3c8cb2e8-20250830135142417.svg)：密文的消息认证码 (MAC tag)。

Alice 将这个组合后的数据包发送给 Bob。

------

### **ECIES 解密流程 (Decryption)**

Bob 收到了 Alice 发送过来的加密数据包 ![img](images/readme/7ae278cbaa19b3cbc081f2cabcd39a4b-20250830135142417.svg)。现在他需要使用自己的私钥来解密它。

#### **第一步：分解加密数据**

Bob 首先从接收到的数据包中分离出三个部分：

- Alice 的临时公ૉ ![img](images/readme/dd1caa3f2e1582dab2cf9bfdb21b7556-20250830135142392.svg)
- 密文 ![img](images/readme/b891664b42113aee13f0bac25eb998e5-20250830135142412.svg)
- MAC 标签 ![img](images/readme/56c1b0cb7a48ccf9520b0adb3c8cb2e8-20250830135142417.svg)

#### **第二步：生成相同的共享密钥**

这是解密流程的关键。Bob 使用自己的**私钥** ![img](images/readme/76463dc54843a62df77e170a160eaa85-20250830135142386.svg) 和 Alice 发送过来的**临时公钥** ![img](images/readme/dd1caa3f2e1582dab2cf9bfdb21b7556-20250830135142392.svg) 来计算共享密钥点 ![img](images/readme/55fc237afbe535f7d8434985b848a6a7-20250830135142394.svg)。

![img](images/readme/23ba8ba805fecc4fe0856e4b5ecfad2b-20250830135142418.svg)

根据前面提到的 ECDH 原理，Bob 计算出的这个点 ![img](images/readme/55fc237afbe535f7d8434985b848a6a7-20250830135142394.svg) 与 Alice 在加密时计算出的点是**完全相同**的，因为 ![img](images/readme/654204cc98ae9546e20d1ee70f7e33d0-20250830135142419.svg)。Bob 同样只取其 x 坐标 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg)。

#### **第三步：使用 KDF 生成相同的对称密钥**

Bob 使用与 Alice 完全相同的 KDF 算法，将共享密钥 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg) 作为输入，派生出加密密钥 ![img](images/readme/c85c3acab643ca1a8c0148a3c3a4cd33-20250830135142403.svg) 和认证密钥 ![img](images/readme/5f92fe34f5f3af5fbbd75d5b0e38b800-20250830135142406.svg)。

![img](images/readme/181ba6d1b763e3c48b832078d4141c17-20250830135142406.svg)

由于输入的 ![img](images/readme/fdd72c0de8458787d41e60ecbc42b68a-20250830135142401.svg) 相同，Bob 生成的 ![img](images/readme/c85c3acab643ca1a8c0148a3c3a4cd33-20250830135142403.svg) 和 ![img](images/readme/5f92fe34f5f3af5fbbd75d5b0e38b800-20250830135142406.svg) 也必然与 Alice 生成的完全相同。

#### **第四步：验证消息认证码 (MAC)**

在解密之前，**必须先验证数据的完整性**。这是一个至关重要的安全步骤，可以防止对密文的恶意篡改攻击。

Bob 使用上一步生成的认证密钥 ![img](images/readme/5f92fe34f5f3af5fbbd75d5b0e38b800-20250830135142406.svg) 和收到的密文 ![img](images/readme/b891664b42113aee13f0bac25eb998e5-20250830135142412.svg)，自己重新计算一次 MAC 标签。

![img](images/readme/5eb6d6a97667f5509d4bc319509d1092-20250830135142423.svg)

然后，他比较自己计算出的标签 ![img](images/readme/44ad9561732864df8495229da3cc9253-20250830135142427.svg) 和从数据包中收到的标签 ![img](images/readme/56c1b0cb7a48ccf9520b0adb3c8cb2e8-20250830135142417.svg)。

- **如果** ![img](images/readme/8d409e07221b4c9155c1aa4d499f8734-20250830135142425.svg)：说明密文在传输过程中没有被篡改，可以继续下一步解密。
- **如果** ![img](images/readme/34a4d42b2296c36f3fd0f12dc44d1928-20250830135142424.svg)：说明数据已被破坏或篡改。**必须立即停止解密过程并丢弃该消息**。

#### **第五步：使用对称解密算法解密消息**

在 MAC 验证通过后，Bob 就可以确信密文是安全可信的。他使用派生出的加密密钥 ![img](images/readme/c85c3acab643ca1a8c0148a3c3a4cd33-20250830135142403.svg) 和相应的对称解密算法来解密密文 ![img](images/readme/b891664b42113aee13f0bac25eb998e5-20250830135142412.svg)。

![img](images/readme/3f54f7bd05253e25f0814c4db466074e-20250830135142427.svg)

如果一切正常，Bob 就能成功恢复出 Alice 发送的原始消息 ![img](images/readme/4760e2f007e23d820825ba241c47ce3b-20250830135142411.svg)。