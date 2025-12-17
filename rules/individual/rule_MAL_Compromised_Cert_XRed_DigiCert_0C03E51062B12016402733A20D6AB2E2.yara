import "pe"

rule MAL_Compromised_Cert_XRed_DigiCert_0C03E51062B12016402733A20D6AB2E2 {
   meta:
      description         = "Detects XRed with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-14"
      version             = "1.0"

      hash                = "5071cd8e8dd184b8eb564f084fc0afb2663b1f7c1cfa84c89a737c4c38f298e0"
      malware             = "XRed"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RONALDO RODRIGUES SANTANA 22670573878"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:03:e5:10:62:b1:20:16:40:27:33:a2:0d:6a:b2:e2"
      cert_thumbprint     = "5C84CE57008546AA49AEF5DEA5F3680247137D0D"
      cert_valid_from     = "2024-08-14"
      cert_valid_to       = "2025-08-14"

      country             = "BR"
      state               = "Sao Paulo"
      locality            = "CAMPINAS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:03:e5:10:62:b1:20:16:40:27:33:a2:0d:6a:b2:e2"
      )
}
