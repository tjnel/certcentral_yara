import "pe"

rule MAL_Compromised_Cert_SoftwareCloud_V2_GlobalSign_24CFDFAC551B761D796E6F40 {
   meta:
      description         = "Detects SoftwareCloud V2 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-29"
      version             = "1.0"

      hash                = "5626a3ac004ec2b1e075fa74e25188d7e30438b089b79bf93774fa1a3dd1dbfe"
      malware             = "SoftwareCloud V2"
      malware_type        = "Unknown"
      malware_notes       = "This malware is part of a campaign of inauthentic software. More research is likely needed: https://x.com/andrewdanis/status/1919585650413629680?s=20"

      signer              = "VRIKSH ADVISORS PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "24:cf:df:ac:55:1b:76:1d:79:6e:6f:40"
      cert_thumbprint     = "D14CF121D80F13CBADB623EC419510D1691C5102"
      cert_valid_from     = "2025-07-29"
      cert_valid_to       = "2026-07-30"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "aashish.vrikshadvisors@gmail.com"
      rdn_serial_number   = "U74120DL2008PTC181602"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "24:cf:df:ac:55:1b:76:1d:79:6e:6f:40"
      )
}
