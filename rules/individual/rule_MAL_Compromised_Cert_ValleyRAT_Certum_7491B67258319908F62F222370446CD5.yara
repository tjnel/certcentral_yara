import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_7491B67258319908F62F222370446CD5 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "d8ec7795909f69b8e4945c38bd362d321f3041a71d2d6cd98d146f6bd47a1e0c"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhijiang Tangqin Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "74:91:b6:72:58:31:99:08:f6:2f:22:23:70:44:6c:d5"
      cert_thumbprint     = "BF8029487FBCED42B7F8959D180E892475AE4C53"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2026-05-09"

      country             = "CN"
      state               = "Hubei"
      locality            = "Zhijiang"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "74:91:b6:72:58:31:99:08:f6:2f:22:23:70:44:6c:d5"
      )
}
