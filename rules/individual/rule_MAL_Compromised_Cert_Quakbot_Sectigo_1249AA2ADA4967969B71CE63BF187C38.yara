import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_1249AA2ADA4967969B71CE63BF187C38 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-04"
      version             = "1.0"

      hash                = "0dc710737c12ea1c1215fbd39e00347649fff1fb0e512287c86873f66a9f0a35"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Umbrella LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38"
      cert_thumbprint     = "BE99FDA34C1567D7FE65AD5DE01CE54E9673CEB4"
      cert_valid_from     = "2020-09-04"
      cert_valid_to       = "2021-09-04"

      country             = "RU"
      state               = "???"
      locality            = "Krasnoyarsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38"
      )
}
