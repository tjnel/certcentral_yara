import "pe"

rule MAL_Compromised_Cert_XWorm_Certum_5CB4CC8D31F6B00C0CAF09CB23945CFD {
   meta:
      description         = "Detects XWorm with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-28"
      version             = "1.0"

      hash                = "4e196693e5613b4585e4dd4ae694e21a0bf90854d916629e465ad2cfcc1e945a"
      malware             = "XWorm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Open Source Developer, Qiang Zhang"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "5c:b4:cc:8d:31:f6:b0:0c:0c:af:09:cb:23:94:5c:fd"
      cert_thumbprint     = "68B94BAF09EDC2422CB70291143980A518EFF2B1"
      cert_valid_from     = "2024-10-28"
      cert_valid_to       = "2025-10-28"

      country             = "CN"
      state               = "陕西省"
      locality            = "汉中市"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "5c:b4:cc:8d:31:f6:b0:0c:0c:af:09:cb:23:94:5c:fd"
      )
}
