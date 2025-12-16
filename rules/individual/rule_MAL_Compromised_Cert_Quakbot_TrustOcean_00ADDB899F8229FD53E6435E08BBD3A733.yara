import "pe"

rule MAL_Compromised_Cert_Quakbot_TrustOcean_00ADDB899F8229FD53E6435E08BBD3A733 {
   meta:
      description         = "Detects Quakbot with compromised cert (TrustOcean)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-25"
      version             = "1.0"

      hash                = "d617ac91f216f3fb38c60b1c5bb1f623805d69fdf076636167bb09adfba5af67"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "U.K. STEEL EXPORTS LIMITED"
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "00:ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33"
      cert_thumbprint     = "DB1E0168B0A62E827745B3499B23A0F41746359D"
      cert_valid_from     = "2021-03-25"
      cert_valid_to       = "2022-03-25"

      country             = "GB"
      state               = "???"
      locality            = "Wattsville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "00:ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33"
      )
}
