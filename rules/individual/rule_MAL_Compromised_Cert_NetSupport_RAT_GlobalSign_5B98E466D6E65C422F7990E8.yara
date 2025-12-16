import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_5B98E466D6E65C422F7990E8 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-06-24"
      version             = "1.0"

      hash                = "fb76386ce3f17a25d59046a70cc05898bcccc7422ab92681777071e46d8943e5"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "DAMOKLES SECURITY INNOVATIONS LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5b:98:e4:66:d6:e6:5c:42:2f:79:90:e8"
      cert_thumbprint     = "6474103BB486B38FA949EAA4322C8CDD857CAF00"
      cert_valid_from     = "2022-06-24"
      cert_valid_to       = "2023-03-05"

      country             = "CA"
      state               = "Alberta"
      locality            = "Airdrie"
      email               = "A.Campbell@guarantaccess.com"
      rdn_serial_number   = "2120160458"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5b:98:e4:66:d6:e6:5c:42:2f:79:90:e8"
      )
}
