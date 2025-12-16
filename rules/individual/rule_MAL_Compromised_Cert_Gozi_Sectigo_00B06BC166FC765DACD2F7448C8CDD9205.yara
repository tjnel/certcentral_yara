import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_00B06BC166FC765DACD2F7448C8CDD9205 {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-12"
      version             = "1.0"

      hash                = "31b94c5a94aa8ce7e187360b0dc702b473d1c5d498d4de26f137b272ccbadaed"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GAS Avto, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05"
      cert_thumbprint     = "BB3BADBF68C50BA24DBF66D17799857D7D1BAFF1"
      cert_valid_from     = "2021-03-12"
      cert_valid_to       = "2022-03-12"

      country             = "SI"
      state               = "???"
      locality            = "Ljubljana"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05"
      )
}
