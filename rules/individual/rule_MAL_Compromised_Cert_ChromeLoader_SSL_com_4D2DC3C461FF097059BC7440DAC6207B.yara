import "pe"

rule MAL_Compromised_Cert_ChromeLoader_SSL_com_4D2DC3C461FF097059BC7440DAC6207B {
   meta:
      description         = "Detects ChromeLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-10-12"
      version             = "1.0"

      hash                = "147e1b5a750fbfd8863449d523e3d6d110defceb74ad9cdb7c939ab75ffa2180"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LIMESTONE DIGITAL LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4d:2d:c3:c4:61:ff:09:70:59:bc:74:40:da:c6:20:7b"
      cert_thumbprint     = "2AAE66915908A703D5059DA2FCF4D5245B78BB30"
      cert_valid_from     = "2022-10-12"
      cert_valid_to       = "2023-10-12"

      country             = "GB"
      state               = "???"
      locality            = "Stoke-On-Trent"
      email               = "???"
      rdn_serial_number   = "14347919"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4d:2d:c3:c4:61:ff:09:70:59:bc:74:40:da:c6:20:7b"
      )
}
