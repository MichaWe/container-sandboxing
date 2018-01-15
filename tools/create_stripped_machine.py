#!/usr/bin/env python3

import sys
import os
import docker
import fnmatch
import tempfile
import csv
import random
import tarfile
import shutil
import getopt
from io import BytesIO

STAGING_DIR = "staging"

try:
    options, arguments = getopt.getopt(sys.argv[1:], "", ["exclude=", "include="])
    if len(arguments) != 3:
        raise Exception("Invalid number of arguments specified")

    docker_file, tracing_file, container_id = arguments
    exclude_files = {path for option, path in options if option == "--exclude"}
    include_files = {path for option, path in options if option == "--include"}
except Exception as e:
    print("{}".format(e))
    print ("Usage: {} <Dockerfile> <Tracing CSV> <Source Container>".format(sys.argv[0]))
    sys.exit(1)

exclude_files.add("/proc/*")
exclude_files.add("/sys/*")
exclude_files.add("/dev/*")

# Try to access the container
client = docker.from_env()
try:
    container = client.containers.get(container_id)
except:
    print("Container {} not found".format(container_id))
    sys.exit(1)

# Try to open the tracing file
print("Read tracing file.")
try:
    fd = open(tracing_file, "r")
    reader = csv.reader(fd, delimiter=';', quotechar='"', quoting=csv.QUOTE_ALL, dialect='unix')
except:
    print("Failed to read csv file {}".format(tracing_file))
    sys.exit(1)

# Filter all files that were accessed
print("Include: {}".format(include_files))
files = set(include_files)
for item in reader:
    if item[1] != "syscall" or item[3] not in ["open", "unlink"] or int(item[7]) < 0:
        continue
    filename = item[10][1:-1]
    filename = os.path .join(container.attrs.get("Config", dict()).get("WorkingDir", "/"), filename)
    filename = os.path.normpath(filename)
    if item[3] == "open":
        files.add(filename)
    elif filename in files:
        files.remove(filename)

if exclude_files:
    print("Following files will be excluded:")
    filtered_files = {file for file in files if any([exclude for exclude in exclude_files if fnmatch.fnmatch(file, exclude)])}
    print("  {}".format("\n  ".join(filtered_files)))
    files.difference_update(filtered_files)

files.add("/lib64/ld-linux-x86-64.so.2")
work_root = "{}/.compress_root_{}".format(tempfile.gettempdir(), random.randint(0, 1000000))
print("Setup work environment at {}".format(work_root))
if not os.path.isdir(work_root):
    os.makedirs(work_root)

print("Copy accessed files to staging root")
staging_path = os.path.join(work_root, STAGING_DIR)
working_files = set(files)
done_files = set()
while len(working_files) > 0:
    file = working_files.pop()
    dest_path = os.path.normpath("{}/{}".format(staging_path, file))
    dest_dir = os.path.dirname(dest_path)
    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)

    try:
        response, stats = container.get_archive(file)
        data = BytesIO(response.read())
        t = tarfile.TarFile(fileobj=data, mode="r")
        t.extractall(dest_dir) 

        linkTarget = stats.get('linkTarget')
        if linkTarget and linkTarget not in done_files:
            working_files.add(linkTarget)

        print("Copied file {}".format(file))
        done_files.add(file)
    except Exception as e:
        print("Failed to copy container file {}".format(file))

print("Generate Dockerfile")
docker_file_path = os.path.join(work_root, "Dockerfile")
shutil.copy(docker_file, docker_file_path)

docker_fileobj = open(docker_file_path, "a")
docker_fileobj.write("\n")
docker_fileobj.write("COPY [\"{}/\", \"/\"]\n".format(STAGING_DIR))
docker_fileobj.close()

stripped_container_image_tag = "{}_stripped".format(container_id)
print("Building container with tag {}".format(stripped_container_image_tag))
try:
    client.images.build(path=work_root, nocache=True, tag=stripped_container_image_tag, rm=True)
except Exception as e:
    print("Container creation failed with error {}".format(e))

print("Remove build root {}".format(work_root))
shutil.rmtree(work_root)

print("Done")
