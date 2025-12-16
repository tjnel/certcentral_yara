import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00F675139EA68B897A865A98F8E4611F00 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-03"
      version             = "1.0"

      hash                = "c2482679c665dbec35164aba7554000817139035dc12efc9e936790ca49e7854"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "BS TEHNIK d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00"
      cert_thumbprint     = "06D46EE9037080C003983D76BE3216B7CAD528F8"
      cert_valid_from     = "2020-12-03"
      cert_valid_to       = "2021-12-03"

      country             = "SI"
      state               = "???"
      locality            = "Lukovica"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00"
      )
}
