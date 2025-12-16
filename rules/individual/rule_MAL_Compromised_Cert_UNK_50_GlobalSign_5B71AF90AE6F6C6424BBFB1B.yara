import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_5B71AF90AE6F6C6424BBFB1B {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-05"
      version             = "1.0"

      hash                = "ef2d8f433a896575442c13614157261b32dd4b2a1210aca3be601d301feb1fef"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Fukoku TOKAI(Shanghai) Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5b:71:af:90:ae:6f:6c:64:24:bb:fb:1b"
      cert_thumbprint     = "94EEBFC9A334B52FE42535DD0F2D4B052FB3D3D5"
      cert_valid_from     = "2024-11-05"
      cert_valid_to       = "2025-11-06"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "dev@fukokutokai.com"
      rdn_serial_number   = "91310000566556497T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5b:71:af:90:ae:6f:6c:64:24:bb:fb:1b"
      )
}
