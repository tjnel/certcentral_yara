import "pe"

rule MAL_Compromised_Cert_LummaStealer_GlobalSign_0C785890CB7CF34C41D06B6C {
   meta:
      description         = "Detects LummaStealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-15"
      version             = "1.0"

      hash                = "9fcdb3db8b8a300150dad2d92e24601ec1f052bdbca08e611489f2fdb814305b"
      malware             = "LummaStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Maibond Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:78:58:90:cb:7c:f3:4c:41:d0:6b:6c"
      cert_thumbprint     = "785eef75d9aa8b8be3d677fd8502447cf675f7becf4198c1570aedf0b70d622c"
      cert_valid_from     = "2024-10-15"
      cert_valid_to       = "2025-10-16"

      country             = "CN"
      state               = "Fujian"
      locality            = "Fuzhou"
      email               = "???"
      rdn_serial_number   = "91350104MA2Y639F25"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:78:58:90:cb:7c:f3:4c:41:d0:6b:6c"
      )
}
