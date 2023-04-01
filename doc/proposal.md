# Problem Statement

In the software world today, we are increasingly "chefs, not farmers" meaning
thanks to the tsunami of open source software available, instead of building
every single component in-house, most of our software development effort goes
towards curating various pieces and concocting a final product from them. The
downside however is that ascertaining the provenance and quality of said
components often referred to as "software supply chain", becomes critical,
otherwise the engineering resources are diverted from development to
validation.

# Requirements

**R1**: **MUST** generate SBOM given a container image
**R2**: Every item in the container image **MUST** be accounted for
**R3**: **MUST** be able to push SBOM artifacts along with the container image

# References

[1] https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
