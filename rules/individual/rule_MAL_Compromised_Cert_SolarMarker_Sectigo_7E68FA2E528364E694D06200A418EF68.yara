import "pe"

rule MAL_Compromised_Cert_SolarMarker_Sectigo_7E68FA2E528364E694D06200A418EF68 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-05"
      version             = "1.0"

      hash                = "5ef62c7d66c9f9470658e647afd257cbc087056ec07b4eafd7879682701cd05a"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "C.T.M. d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "7e:68:fa:2e:52:83:64:e6:94:d0:62:00:a4:18:ef:68"
      cert_thumbprint     = "8B5C3016639149FFA34DCF63FA0C30254A7FF178"
      cert_valid_from     = "2020-11-05"
      cert_valid_to       = "2021-11-05"

      country             = "SI"
      state               = "???"
      locality            = "Liubliana"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "7e:68:fa:2e:52:83:64:e6:94:d0:62:00:a4:18:ef:68"
      )
}
