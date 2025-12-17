import "pe"

rule MAL_Compromised_Cert_FakeBat_Sectigo_5537908F151E7077149B1954A28632B4 {
   meta:
      description         = "Detects FakeBat with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-02-15"
      version             = "1.0"

      hash                = "b0804a60d9992f6af63e247258fae4715816c19a76341f1cd2245fd1385a66f3"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "ASHANA GLOBAL LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "55:37:90:8f:15:1e:70:77:14:9b:19:54:a2:86:32:b4"
      cert_thumbprint     = "00208976D65AF03024D301306F19C74C3F9EDB22"
      cert_valid_from     = "2023-02-15"
      cert_valid_to       = "2024-02-16"

      country             = "GB"
      state               = "Buckinghamshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "55:37:90:8f:15:1e:70:77:14:9b:19:54:a2:86:32:b4"
      )
}
