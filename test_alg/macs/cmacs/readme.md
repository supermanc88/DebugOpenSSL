注意：
    3des和des在openssl 3.x默认的provider中被移除，需手动加载legacy provider

```c
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
...
OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
if (legacy == NULL) {
    // 处理加载失败
}
...
OSSL_PROVIDER_unload(legacy);
```

还需要设置环境变量
```bash
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules
```

