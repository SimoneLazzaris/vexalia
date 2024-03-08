#!/usr/bin/python3
import json
import tempfile
import os
import fastapi
import subprocess
import logging
import logging


def ref_by_purl(sbom, purl):
    for comp in sbom["components"]:
        if comp["purl"] == purl:
            return comp["bom-ref"]
    return None

def add_vex(sbom):
    with tempfile.TemporaryDirectory() as tempdir:
        sbomfile=os.path.join(tempdir,"sbom.json")
        vexfile=os.path.join(tempdir,"vex.json")
        with open(sbomfile, "wt") as f:
            json.dump(sbom,f)
        cmdline=["/usr/local/bin/trivy", "sbom", sbomfile, "--format=cyclonedx",  "-o", vexfile]

        res = subprocess.run(cmdline, capture_output = True, text=True)
        res.check_returncode()
        if res.returncode != 0:
            logging.error("STDOUT: %s", res.stdout)
            logging.error("STDERR: %s", res.stderr)
            raise subprocess.CalledProcessError
        with open(vexfile) as f:
            vex=json.load(f)

    sbom["vulnerabilities"]=[]

    for v in vex["vulnerabilities"]:
        for affect in v["affects"]:
            ref = affect["ref"]
            fixedRef = ref_by_purl(sbom, ref)
            if fixedRef != None:
                affect["ref"] = fixedRef
                logging.info("%s: %s -> %s", v["id"], ref, fixedRef)
                sbom["vulnerabilities"].append(v)
    return sbom

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

app=fastapi.FastAPI()

@app.post("/sbom/vulnerabilities")
def vulnerabilities(sbom: dict) -> dict:
    sbom = add_vex(sbom)
    return sbom

@app.get("/")
def index() -> dict:
    return {"name": "vexalia", "version": "1.0"}
