# FIDOでやりたいことの整理
+ すぐに試せる環境作り
  + FIDO Serverをあのlibraryを使って作る
  + web/iOS/AndroidのClient
+ 疑問に対する自身の考えを出す


## MacOS / iOS
### 現状
+ version
  + mac: 12.5.1
  + ipad: 15.7
+ できること
  + 現在は、iCould key chaineを有効にしたらpasskey使える、しなかったら使えないくらい
  + macではpasskeyはつかえないか。
  + 実際に別デバイスで利用できること確認できてないな。

### 次
+ version
  + mac: 13
  + ios 16
  + Safari 16
+ できるようになること
  + passkeyを使った
    + iCloud Key Chaineを無効にすると, デバイスの生体認証そのものが使えなくなるな
  + mac/ipad側でandroidをroaming authenticatorとして使う

+ 現状
  + iPadを16にupgrade中
  + macbookをVenturaに上げる

 

## 解消する疑問
### attestation format apple の検証
+ libraryでサポートされているな.

### [attestation format](https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats)
+ packed:
  + Chrome, Mac Book as platform authenticator
+ android-safetynet:
  + Chrome, Pixel as platform authenticator
+ none:
  + Safari, iCloud keychange on iPad (passkey)
  + Chrome, Pixel as roaming authenticator
  + Chrome, iPad as roaming authenticator
+ apple:
  + Safari, iCloud keychange off iPad
  + Safari, MacBook as platform authenticator
+ fido-u2f:
  + Chroem, yubikey
+ tpm: -
+ android-key: -

### PINをなしにすることできるか
+ server側でPIN or 生体認証を確認することができるか？

+ User Verification Methodってので伝えることはできるのか
  + https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods
  + https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/api/common/UserVerificationMethodExtension

+ library的には未サポートな感じ
  + https://github.com/duo-labs/webauthn/issues/134

+ Android/Chromeでのみ帰ってきた　
  + extensionsに `uvm:true` 渡したら, ClientExtensionResultsがかえって来る.
  + User Verification Methods: 134
  + なんか, 使われたものというか, サポートしている要素返してる気が... USER_VERIFY_FINGERPRINT, USER_VERIFY_PATTERN, USER_VERIFY_PASSCODE
    + https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/api/common/UserVerificationMethods

+ 一方で, 例えばAndroidとか, 指紋認証すぐ反応しなくなるから, PINを制限するとかしないほうがいいと思う.

### passkeyって、server側で使うか使わないか判別できるか？
+ iCloud keychainを、onにするとpasskey利用/offにするとpasskey使わないとなってそう
+ AAGUIDで見分けることができるかな？
+ attestation formatが違っているが, 正直意図的なものかどうかは怪しい...
  + passkey:none
  + not passkey:apple


### passkeyにした時の、SNS乗っ取りの対応をどうするか？

### 複数のRPID/Originにする場合どうするか？

### roaming authenticatorを許可する場合, attestationはちゃんと検証したいところ
+ AuthenticatorAttachmentだけではない
+ しかし、現状、どこまで確認しているか？



## ngrok settings
```
$ ngrok config add-authtoken (token)

$ ngrok config edit
version: "2"
authtoken: (token)
tunnels:
  fido-server:
    addr: 8080
    proto: http
    subdomain: fido-kokukuma
  web-client:
    addr: 8081
    proto: http
    subdomain: client-kokukuma
```

## metadata
+ metadata package, v3への対応ができてないぽい.
  + github.com/duo-labs/webauthn/metadata/metadata.go
+ 修正が必要な点
  + 1. getMetdataTOCSigningTrustAnchorを追加
  + 2. revoke.VerifyCertificateをコメントアウト...
  + 3. MetadataStatementの型変更
  + 4. AuthenticatorAttestationTypeをstringにする
+ これ待つほうがいいかな.
  + https://github.com/duo-labs/webauthn/pull/146/files#diff-bc1663385db50e33df147e8b0da3b8694f87707081a013c63bc8c6eacb9984d5
  + それまではv2使うか?
  + でもトークン取らなきゃいけないとかだるいよな...
+ 取得できたの
  + たしかに、packedとandroid-safetynetだけ

## iOS/Androidでの試し
+ 昔やった試し
  + /Users/kokukuma/Desktop/ios-app/fido2
  + /Users/kokukuma/developmment/fido2-codelab
  + /Users/kokukuma/developmment/authentication/authentication
+ この辺のことを雰囲気やる
  + https://docs.flutter.dev/get-started/install/macos
  + https://docs.flutter.dev/get-started/codelab





