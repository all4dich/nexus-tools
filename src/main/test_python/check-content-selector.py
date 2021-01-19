from nexus_tools.common import NexusOSS
import argparse
import json
import re

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--user", required=True)
    arg_parser.add_argument("--password", required=True)
    arg_parser.add_argument("--url", required=True)
    args = arg_parser.parse_args()
    nexus_connector = NexusOSS(args.user, args.password, args.url)
    result_str = nexus_connector.get_content_selectors()
    result = json.loads(result_str)

    content_selector = filter(lambda each_cs: re.compile(r"nx-docker-person-.*").match(each_cs["name"]), result)
    cs_size = 0
    for filtered_cs in content_selector:
        print("Content selector = " + filtered_cs['name'])
        cs_size = cs_size+ 1
    print(f"Total Size = {cs_size}")

