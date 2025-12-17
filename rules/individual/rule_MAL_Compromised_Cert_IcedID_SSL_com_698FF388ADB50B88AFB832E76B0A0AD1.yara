import "pe"

rule MAL_Compromised_Cert_IcedID_SSL_com_698FF388ADB50B88AFB832E76B0A0AD1 {
   meta:
      description         = "Detects IcedID with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-01-30"
      version             = "1.0"

      hash                = "244e55adeb71ae1cbd57af87dd4fa0c2f1143233ffddf254da27a721c61a63c4"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "BELLAP LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1"
      cert_thumbprint     = "D1DE8B155C9D45ADB47BA96BDC8670C84BB4390A"
      cert_valid_from     = "2023-01-30"
      cert_valid_to       = "2023-12-18"

      country             = "GB"
      state               = "England"
      locality            = "Sandhurst"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1"
      )
}
