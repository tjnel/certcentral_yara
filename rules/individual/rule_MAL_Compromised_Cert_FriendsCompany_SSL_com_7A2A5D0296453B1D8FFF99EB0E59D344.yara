import "pe"

rule MAL_Compromised_Cert_FriendsCompany_SSL_com_7A2A5D0296453B1D8FFF99EB0E59D344 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-12"
      version             = "1.0"

      hash                = "eb53a94b153191bc14904748a21134aba8eab77701f04afdf178a5b83c57c3af"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Pinkou (SH) Culture Communication Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7a:2a:5d:02:96:45:3b:1d:8f:ff:99:eb:0e:59:d3:44"
      cert_thumbprint     = "A918B378A3559D19C9D9400FF8441EB86990D309"
      cert_valid_from     = "2024-03-12"
      cert_valid_to       = "2025-03-11"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7a:2a:5d:02:96:45:3b:1d:8f:ff:99:eb:0e:59:d3:44"
      )
}
