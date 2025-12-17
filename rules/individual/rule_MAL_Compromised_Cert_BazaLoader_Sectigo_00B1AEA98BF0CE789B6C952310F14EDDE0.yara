import "pe"

rule MAL_Compromised_Cert_BazaLoader_Sectigo_00B1AEA98BF0CE789B6C952310F14EDDE0 {
   meta:
      description         = "Detects BazaLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-01"
      version             = "1.0"

      hash                = "7697108c8e032dc97dbcda51ba54a82d85973137faacd19fb306c0217d50cfa2"
      malware             = "BazaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Absolut LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
      cert_thumbprint     = "3B48DE4FB410ABDC0F7F4B0852A265221A22951E"
      cert_valid_from     = "2020-10-01"
      cert_valid_to       = "2021-10-01"

      country             = "RU"
      state               = "???"
      locality            = "Krasnoyarsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
      )
}
