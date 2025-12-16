import "pe"

rule MAL_Compromised_Cert_Unknown_Verokey_01ADCD97B8AE44D40185DC60C1D2AE56 {
   meta:
      description         = "Detects Unknown with compromised cert (Verokey)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-21"
      version             = "1.0"

      hash                = "00748bd6b97e6ea3b46750c45691689401ab32505387d963c3efdcfa758b6227"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "山西荣升源科贸有限公司"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey Secure Code"
      cert_serial         = "01:ad:cd:97:b8:ae:44:d4:01:85:dc:60:c1:d2:ae:56"
      cert_thumbprint     = "B5EA2F1CEAB2BD463277A47A356C7CA4FB048469"
      cert_valid_from     = "2025-01-21"
      cert_valid_to       = "2025-06-13"

      country             = "CN"
      state               = "山西省"
      locality            = "太原市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey Secure Code" and
         sig.serial == "01:ad:cd:97:b8:ae:44:d4:01:85:dc:60:c1:d2:ae:56"
      )
}
