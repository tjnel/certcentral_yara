import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_54CD7AE1C27F1421136ED25088F4979A {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-22"
      version             = "1.0"

      hash                = "f987e604cea843136237baea2181b45467bbbf2155fdd7c51350dfa84ec051cc"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "ABBYMAJUTA LTD LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a"
      cert_thumbprint     = "ACDE047C3D7B22F87D0E6D07FE0A3B734AD5F8AC"
      cert_valid_from     = "2021-03-22"
      cert_valid_to       = "2022-03-22"

      country             = "GB"
      state               = "Cambridgeshire"
      locality            = "Peterborough"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a"
      )
}
