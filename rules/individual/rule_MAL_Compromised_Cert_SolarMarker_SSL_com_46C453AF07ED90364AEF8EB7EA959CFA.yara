import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_46C453AF07ED90364AEF8EB7EA959CFA {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-15"
      version             = "1.0"

      hash                = "4788925332fc6128c895b0e0736a1d7d90e3891f2abb456523cbf0c1ced7d1e2"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Heart Craft Brewery s. r. o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "46:c4:53:af:07:ed:90:36:4a:ef:8e:b7:ea:95:9c:fa"
      cert_thumbprint     = "56ECF072A9C4872B186254B30CEC2469166E4D63"
      cert_valid_from     = "2024-03-15"
      cert_valid_to       = "2025-03-15"

      country             = "SK"
      state               = "Bratislava Region"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "51 278 278"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "46:c4:53:af:07:ed:90:36:4a:ef:8e:b7:ea:95:9c:fa"
      )
}
