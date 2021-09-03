# Corelight Threat Hunting Guide (working copy)

This repository serves as the working data for the Corelight Threat Hunting Guide. The source prose which is maintained here is periodically put through editing, layout, and graphic design, and then published as a PDF file and distributed by Corelight, Inc. (“Corelight”). There is not a definitive schedule for these actions, but historically a new release is made every six to twelve months.

If you would like the most recent version of the Corelight Threat Hunting Guide you can find it [here](https://www3.corelight.com/corelights-introductory-guide-to-threat-hunting-with-zeek-bro-logs).

The PDF version is a point-in-time snapshot of content at the time of publishing and may not contain all of the content in this repository.

## The fine print / License

This work is maintained by Corelight and members of the Corelight community, and while it references the Zeek project and Zeek logs, it is not part of the Zeek project (though any member of the Zeek community of users is welcome to contribute here).

All work is maintained under the [Creative Commons Attribution-NonCommercial-ShareAlike license](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode). Please read this license, understand it, and decide whether you agree with it before deciding whether to contribute to this project. If you contribute to the project, you are agreeing to the license terms.

Corelight, Inc. owns the work here, and it is used for Corelight marketing purposes (e.g. webinars, printed collateral, website prose). Any content you contribute here can be used for these purposes. This content may not be used for commercial purposes by any other organization besides Corelight, Inc.

Corelight, Inc. retains the right to freely recognize contributors listed in the CREDITS file in this repository, and publish, electronically and in print, their posts, likeness, and name from GitHub. If you wish to be recognized for your contributions, please place your name in the [CREDITS file](./CREDITS.md).

The content here may be freely shared.

Corelight, Inc. maintains editorial control over the content here. All contributions will be reviewed, but Corelight reserves the right to:
- Accept a contribution as-is
- Edit a contribution prior to or after acceptance
- Decline a contribution

However, the people that make up Corelight are exactly that: **people**. We are sharing this content with the world because we want community engagement. We want our customers and members of the Zeek community to tell us if anything is technically inaccurate or if a particular threat hunt does not work on their network or at a certain scale, because that information will benefit everyone who reads this guide in the future.

## How to contribute

There are two main ways to contribute:

- Forking the repository, making changes, and submitting those changes back to our repository via a pull request
- Opening an [issue](https://github.com/corelight/threat-hunting-guide/issues) pointing out any issues with the content, or offering suggestions of changes or additions

Where possible, contributions should be aligned to the [MITRE ATT&CK Framework](https://attack.mitre.org/).
Each ATT&CK Tactic (goal or phase) is housed in its own folder, numbered with the numbers assigned by MITRE. Inside of each Tactic folder is a file for each Technique. Technique files should have a prefix matching the Technique number assigned by MITRE.

## Table of Contents

|Section|
|---|
|[Introduction](./0_Introduction)|
|[TA0001: Initial Access](./TA0001_Initial_Access)|
|[TA0002: Execution](./TA0002_Execution)|
|[TA0003: Persistence](./TA0003_Persistence)|
|[TA0005: Defense Evasion](./TA0005_Defense_Evasion)|
|[TA0006: Credential Access](./TA0006_Credential_Access)|
|[TA0007: Discovery](./TA0007_Discovery)|
|[TA0008: Lateral Movement](./TA0008_Lateral_Movement)|
|[TA0009: Collection](./TA0009_Collection)|
|[TA0010: Exfiltration](./TA0010_Exfiltration)|
|[TA0011: Command and Control](./TA0011_Command_and_Control)|

## Formatting/style suggestions

Log names should be formatted as monospace text and referenced by the log name, not the on-disk filename, like so:  ``Check in the `conn` log...``
> Check in the `conn` log...

Field names should also be formatted as monospace text, like so: ``The `cookie` field can sometimes contain a username...``
> The `cookie` field can sometimes contain a username...

Value literals should also be formatted as monospace text, like so: ``If the number of bytes is `532` then...``
> If the number of bytes is `532` then...
