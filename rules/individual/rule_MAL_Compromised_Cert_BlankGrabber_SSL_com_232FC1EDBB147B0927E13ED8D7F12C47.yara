import "pe"

rule MAL_Compromised_Cert_BlankGrabber_SSL_com_232FC1EDBB147B0927E13ED8D7F12C47 {
   meta:
      description         = "Detects BlankGrabber with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-19"
      version             = "1.0"

      hash                = "9203d748f205c44735ccb43f9312cc818693de205075d8c0d3a3582eca6e2e63"
      malware             = "BlankGrabber"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nguyễn Văn Tuấn"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA ECC R2"
      cert_serial         = "23:2f:c1:ed:bb:14:7b:09:27:e1:3e:d8:d7:f1:2c:47"
      cert_thumbprint     = "9AE50F22379325CC7A0AEBCD570E8BDD66F16AAD"
      cert_valid_from     = "2024-12-19"
      cert_valid_to       = "2025-12-19"

      country             = "VN"
      state               = "Thái Bình"
      locality            = "Huyện Hưng Hà"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA ECC R2" and
         sig.serial == "23:2f:c1:ed:bb:14:7b:09:27:e1:3e:d8:d7:f1:2c:47"
      )
}
