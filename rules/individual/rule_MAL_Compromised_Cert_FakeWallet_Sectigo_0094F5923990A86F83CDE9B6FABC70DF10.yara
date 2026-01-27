import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_0094F5923990A86F83CDE9B6FABC70DF10 {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-23"
      version             = "1.0"

      hash                = "4f55c34f37b1881ff46a27354262a657a7edfed898852974fc6b42aad6190028"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer impersonating Neon Wallet"

      signer              = "Wuhan Handing Intelligent Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:94:f5:92:39:90:a8:6f:83:cd:e9:b6:fa:bc:70:df:10"
      cert_thumbprint     = "DACD90BF4D4D77F7A74C21993BFB4C828BB12699"
      cert_valid_from     = "2025-12-23"
      cert_valid_to       = "2026-12-23"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91420106MA49BE5D9M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:94:f5:92:39:90:a8:6f:83:cd:e9:b6:fa:bc:70:df:10"
      )
}
