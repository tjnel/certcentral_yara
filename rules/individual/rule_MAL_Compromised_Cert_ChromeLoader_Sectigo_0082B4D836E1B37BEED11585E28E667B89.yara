import "pe"

rule MAL_Compromised_Cert_ChromeLoader_Sectigo_0082B4D836E1B37BEED11585E28E667B89 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-16"
      version             = "1.0"

      hash                = "564b8e327a13c948cea21587245b7b0005f786ea57f62bd602ef4ecec66171c6"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Invenivia"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:82:b4:d8:36:e1:b3:7b:ee:d1:15:85:e2:8e:66:7b:89"
      cert_thumbprint     = "40C8C6D3D7275ECD52A099471B5386C97F6B1B16"
      cert_valid_from     = "2023-11-16"
      cert_valid_to       = "2024-11-15"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:82:b4:d8:36:e1:b3:7b:ee:d1:15:85:e2:8e:66:7b:89"
      )
}
