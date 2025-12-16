import "pe"

rule MAL_Compromised_Cert_AsyncRAT_SSL_com_668C68DB859DBAE5DCE71BFB867F5B93 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-05"
      version             = "1.0"

      hash                = "42ead68d0ff87d03dd4c171648e3ad8deb02c596f78bf4b595433ab60e6ff867"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NGUYEN THANH AN"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "66:8c:68:db:85:9d:ba:e5:dc:e7:1b:fb:86:7f:5b:93"
      cert_thumbprint     = "008CA8EE9073F9B8FBF86FD7F9626890EC7EC349"
      cert_valid_from     = "2025-06-05"
      cert_valid_to       = "2026-06-05"

      country             = "VN"
      state               = "Lâm Đồng"
      locality            = "Đưc Trọng"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "66:8c:68:db:85:9d:ba:e5:dc:e7:1b:fb:86:7f:5b:93"
      )
}
