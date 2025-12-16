import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_3D3FC30099D6C7AEB806D4181992AF90 {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-02"
      version             = "1.0"

      hash                = "04595c3111276f02b6dc2ece0778cb5829c086484aeafa24e0aac3d8479deb4b"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Baltic Auto SIA"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "3d:3f:c3:00:99:d6:c7:ae:b8:06:d4:18:19:92:af:90"
      cert_thumbprint     = "30576D884D8311D503D9CB030FD547DC26D1AB6B"
      cert_valid_from     = "2021-09-02"
      cert_valid_to       = "2022-09-02"

      country             = "LV"
      state               = "Rīga"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "40103318287"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "3d:3f:c3:00:99:d6:c7:ae:b8:06:d4:18:19:92:af:90"
      )
}
