import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_04C57B9205B4533656B302990A86D113 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-27"
      version             = "1.0"

      hash                = "9c699540819d96bfe614049cf31abc8b850bc3f74b19654a06db75fc0ac6db8f"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Tevora Business Solutions, Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Global G3 Code Signing ECC SHA384 2021 CA1"
      cert_serial         = "04:c5:7b:92:05:b4:53:36:56:b3:02:99:0a:86:d1:13"
      cert_thumbprint     = "8D2ACCFDF5149F337C227D2E893DA2151494A692"
      cert_valid_from     = "2022-04-27"
      cert_valid_to       = "2024-03-21"

      country             = "US"
      state               = "California"
      locality            = "Laguna Hills"
      email               = "???"
      rdn_serial_number   = "C2498653"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Global G3 Code Signing ECC SHA384 2021 CA1" and
         sig.serial == "04:c5:7b:92:05:b4:53:36:56:b3:02:99:0a:86:d1:13"
      )
}
