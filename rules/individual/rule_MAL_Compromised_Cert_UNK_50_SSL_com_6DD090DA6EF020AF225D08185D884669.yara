import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_6DD090DA6EF020AF225D08185D884669 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-22"
      version             = "1.0"

      hash                = "96848f20bf3587b160b76c92f6eebad50377585b31d7224579ef158367f5a18c"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "SPECTRUM MS LLP"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6d:d0:90:da:6e:f0:20:af:22:5d:08:18:5d:88:46:69"
      cert_thumbprint     = "1F081D014159073582E90A7481498BC3DE88632A"
      cert_valid_from     = "2025-09-22"
      cert_valid_to       = "2026-09-22"

      country             = "IN"
      state               = "West Bengal"
      locality            = "Kolkata"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6d:d0:90:da:6e:f0:20:af:22:5d:08:18:5d:88:46:69"
      )
}
