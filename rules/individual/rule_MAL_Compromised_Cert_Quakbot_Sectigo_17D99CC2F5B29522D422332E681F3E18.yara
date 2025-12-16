import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_17D99CC2F5B29522D422332E681F3E18 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-12"
      version             = "1.0"

      hash                = "a50992df4e3904b464d2202318046d25e5e072f56fcee0d524ceedcced0db0ed"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "PKV Trading ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18"
      cert_thumbprint     = "969932039E8BF3B4C71D9A55119071CFA1C4A41B"
      cert_valid_from     = "2021-02-12"
      cert_valid_to       = "2022-02-12"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Skævinge"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18"
      )
}
