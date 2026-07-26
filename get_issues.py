import argparse
import json
import requests

API_PATH="/public_api/v1/issue/search"

def load_config(path):
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)

def headers(cfg):
    return {
        "Authorization": cfg["api_key"],
        "x-xdr-auth-id": cfg["key_id"],
        "Content-Type":"application/json",
        "Accept":"application/json"
    }

def build_url(cfg):
    return f'https://{cfg["fqdn"].rstrip("/")}{API_PATH}'

def main():
    ap=argparse.ArgumentParser(description="Cortex Cloud Issues Exporter")
    ap.add_argument("--config",required=True)
    args=ap.parse_args()

    cfg=load_config(args.config)

    print("== Cortex Cloud Issues Exporter ==")
    print("Endpoint :",build_url(cfg))
    print("Page Size:",cfg.get("page_size",1000))
    print("Output   :",cfg.get("output","issues.csv"))

    body={
        "request_data":{
            "filters":cfg.get("filters",[]),
            "search_from":0,
            "search_to":cfg.get("page_size",1000),
            "sort":{"field":"creation_time","keyword":"asc"}
        }
    }

    print("\nExample request body:")
    print(json.dumps(body,indent=2))

    # Uncomment once request schema is validated:
    #
    # r=requests.post(
    #     build_url(cfg),
    #     headers=headers(cfg),
    #     json=body,
    #     timeout=60
    # )
    # print(r.status_code)
    # print(r.text)

if __name__=="__main__":
    main()
