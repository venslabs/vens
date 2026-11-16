# Talks

Where vens has been presented, and where it is going next.

## Upcoming

| Date | Event | City | Format | Language |
|---|---|---|---|---|
| 2026-12-09/10 | KCD Suisse Romande | Geneva (CERN), CH | lightning, 5 min | FR |

## Past

| Date | Event | City | Format | Language | Slides | Video |
|---|---|---|---|---|---|---|
| 2026-11-14 | Capitole du Libre | Toulouse, FR | conference, 55 min | FR | [PDF](assets/capitole-du-libre-2026.pdf) | |
| 2026-09-24 | PlatformCon Live Day Paris | Paris, FR | 30 min | FR | [PDF](assets/platformcon-paris-2026.pdf) | [video](https://www.youtube.com/watch?v=V5gp2R0z7fU) |
| 2026-06-25 | SecureChainCon | online | recorded | EN | | [video](https://www.youtube.com/watch?v=Pnx1nqGAeSY) |

## Questions

What people asked during the talks, with short answers.

??? question "Capitole du Libre, Toulouse, 2026"

    - **How do you make sure vens and Dependency-Track see the same CVEs?** Same SBOM, same Trivy server as Dependency-Track, and vens runs at the same pace as the Dependency-Track scans. A Dependency-Track webhook can trigger it.
    - **Does vens read the runtime context?** No, only the YAML file.
    - **Can I have one context per dependency instead of one for the whole app?** No, the context describes the app. If two services run in different contexts, use one SBOM and one context file per service.
    - **Can vens do the same for SAST?** Not yet. The OWASP method works without a CVE, but vens would need to read SARIF. Open an issue if you want it.

## Photos

### PlatformCon Live Day Paris, 2026

<div class="grid cards" markdown>

<figure markdown>
  [![Full-size photo: the speaker presents the vens architecture on stage](assets/talks/jean-baptiste-poggi-02.jpg)](https://github.com/venslabs/media/blob/main/events/2026-09-24-platformcon-paris/jean-baptiste-poggi-02.jpg)
  <figcaption>Presenting the architecture</figcaption>
</figure>

<figure markdown>
  [![Full-size photo: the speaker on stage in front of a slide about generic scores](assets/talks/jean-baptiste-poggi-04.jpg)](https://github.com/venslabs/media/blob/main/events/2026-09-24-platformcon-paris/jean-baptiste-poggi-04.jpg)
  <figcaption>On stage</figcaption>
</figure>

<figure markdown>
  [![Full-size photo: close-up of the speaker mid-explanation](assets/talks/jean-baptiste-poggi-08.jpg)](https://github.com/venslabs/media/blob/main/events/2026-09-24-platformcon-paris/jean-baptiste-poggi-08.jpg)
  <figcaption>Mid-explanation</figcaption>
</figure>

<figure markdown>
  [![Full-size photo: the speaker at the lectern with a laptop](assets/talks/jean-baptiste-poggi-07.jpg)](https://github.com/venslabs/media/blob/main/events/2026-09-24-platformcon-paris/jean-baptiste-poggi-07.jpg)
  <figcaption>At the lectern</figcaption>
</figure>

</div>

<small>Photos: Jean-Baptiste Poggi, not covered by the vens Apache-2.0 licence.</small>

