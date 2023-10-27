# packager

在设计软件产品升级包的时候，经常遇到以下问题

- 如何防止被直接解包查看
- 如何防止被篡改后重打包
- 单项目有多个升级包类型，如何方便统一验证和区分打包对象权限
- 如何在升级包中维护版本号等 ExtraData
- 如果需要在前端界面上传升级包，如何支持 js 直接获取升级包的 MetaData

本库就是用于解决这些实际环境下的问题的，其使用流程如下

## 准备

1. 生成 ca，然后基于 ca 签发多个子证书（比如不同的升级包是不同的团队维护的，那就需要每组一个单独的证书）
2. 每个组维护一个 32 位主加密 key，用于加密升级包
3. 在对升级包进行打包的时候，确定嵌入到升级包中的 ExtraData（比如版本号、打包时间、兼容性配置等）
4. 确定 ExtraData 是否需要加密，如需加密，则需要再维护一个单独的 32 位 ExtraData key。

```shell
./packager gen-cert --common-name front-end-team
```
**后续的命令行示例均使用相同的简单 key，实际使用中请自行维护一对随机生成的不同的 key。**

## 打包

传入自己的证书和对应的 key，使用 cli 或者 api 打包。

如果不需要加密 ExtraData，可以不传入 `--encrypt-extra-data` 和 `--extra-data-aes-key`，后续流程同理。

```shell
./packager pack --input data.zip --output data.zip.pkg --magic front-end-pkg-v1 \
    --extra-data version=1.2.3 --extra-data build_time=20231201 \
    --encrypt-extra-data \
    --main-data-aes-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --extra-data-aes-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## 解包

传入 ca 证书和对应的 key，使用 cli 或者 api 解包，如果解包成功，则返回内嵌的 ExtraData 和签名证书信息。

```shell
./packager unpack --input data.zip.pkg --output unpack-data.zip
    --main-data-aes-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    --extra-data-aes-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

解包成功则输出

```
extra data:
{
  "build_time": "20231201",
  "version": "1.2.3"
}

end cert:
  subject: CN=front-end-team
  serial: 1698390744295701000
  validity bounds: 2023-10-27 07:12:24 +0000 UTC - 2033-10-27 07:12:24 +0000 UTC
unpack succeeded
```

如果只想获取 ExtraData，可以使用

```shell
./packager get-extra-data --input data.zip.pkg -output data.json \
    --extra-data-aes-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

更多使用说明可以使用 `./packager -h` 查看。

## 常见问题

### 如何验证升级包打包者的权限

如果解包成功，说明此升级包肯定是 ca 签发的子证书签名的，但是本工具内无法验证是否是对应的子证书签名的。
比如前端团队的证书，不能用于打包后端的升级包，可以自行根据证书的 CommonName 等字段进行验证。

### 本工具可以保证升级包的数据不被解密和篡改么

因为使用到了对称加密，所以在密钥泄露的情况下（比如客户端软件，获取密钥只是成本问题），升级包内的数据可能会被解密。
但是还是用到了非对称加密进行签名，所以攻击者无法实现解密后重新打包。

### 前端页面上传升级包如何预先读取 ExtraData

详见 `fileHeader` 对象

- 文件的第 49 个字节为 ExtraData 是否被加密
- 50-57 字节为 uint64 数据代表 ExtraData 的长度，按照此长度继续读取即可

如果 ExtraData 被加密，需要使用自行设计的密钥按照 `AES256-CTR` 模式解密，否则直接 Json 反序列化即可。

注意：此操作不会进行签名验证，仅供用于前端初步判断和信息展示，后端还是要进行完整的校验。