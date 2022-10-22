import os, shutil, yaml, datetime
import sitebuilder.markdownparser as markdownparser

IMAGE_LOCATION = os.path.join("html", "images")
TEMPLATE_LOCATION = os.path.join(".", "templates")

def load_page_config(name, path, group_name):
    with open(os.path.join(path, "prop.yaml"), 'r') as f:
        prop_dict = yaml.load(f, Loader=yaml.SafeLoader)

    update_yml = False

    if prop_dict.get("release_date", "") == "":
        prop_dict["release_date"] = datetime.datetime.now(datetime.timezone.utc)
        update_yml = True

    prop_dict["show_header_section"] = prop_dict.get("show_header_section", True)

    if update_yml:
        with open(os.path.join(path, "prop.yaml"), 'w') as f:
            yaml.dump(prop_dict, f)

    if prop_dict.get("main_image", False):
        prop_dict["main_image"] = "/images/{group_name}/{name}/{image_name}".format(
            group_name=group_name,
            name=name,
            image_name=prop_dict["main_image"].split("/")[-1]
        )

    prop_dict["template_loc"] = os.path.join(group_name, name, "page.html")
    prop_dict["name"] = name
    return prop_dict

def _is_md_folder(path):
    if not os.path.exists(os.path.join(path, "content.md")) or not os.path.exists(os.path.join(path, "prop.yaml")):
        return False

    return True

def _should_copy_image(name, path, image_loc):
    try:
        new_img_loc = os.path.join(image_loc, name)
        if not os.path.exists(new_img_loc):
            return True

        md_img_time = os.path.getmtime(path)
        new_img_time = os.path.getmtime(new_img_loc)

        if md_img_time > new_img_time:
            return True
    except Exception as e:
        print(e)
    return False

def publish_images(group_name, name, path):
    old_image_loc = os.path.join(path, "images")
    if not os.path.exists(old_image_loc):
        return
    if not os.path.exists(os.path.join(IMAGE_LOCATION, group_name)):
        os.makedirs(os.path.join(IMAGE_LOCATION, group_name))

    image_loc = os.path.join(IMAGE_LOCATION, group_name, name)
    if not os.path.exists(image_loc):
        os.makedirs(image_loc)

    images = [(f.name, f.path) for f in os.scandir(old_image_loc) if f.is_file()]

    for img_name, img_path in images:
        if _should_copy_image(img_name, img_path, image_loc):
            shutil.copyfile(img_path, os.path.join(image_loc, img_name))

def _get_markdown_folders(group_name, markdown_folder, total_subfolders=[], prefix_folder=""):
    subfolders =  [(f.name, f.path) for f in os.scandir(os.path.join(markdown_folder, prefix_folder)) if f.is_dir()]
    to_scan = []
    for name, path in subfolders:
        if _is_md_folder(path):
            total_subfolders.append((os.path.join(prefix_folder, name), path))
        else:
            to_scan.append(name)

    for name in to_scan:
        total_subfolders = _get_markdown_folders(group_name,
                                                    markdown_folder,
                                                    prefix_folder=os.path.join(prefix_folder, name),
                                                    total_subfolders=total_subfolders)
    return total_subfolders


def parse_pages(group_name, markdown_folder):
    """
    Parameters:
        group_name: str
            the name of the type of data (eg. blog, writeups/htb_machines)

        markdown_folder:
            the location of the markdown folder for the group (eg. ./markdown_entries/writeups/htb_machines)
    """
    subfolders = _get_markdown_folders(group_name, markdown_folder, total_subfolders=[], prefix_folder="")

    if not os.path.exists(os.path.join(TEMPLATE_LOCATION, group_name)):
        os.mkdir(os.path.join(TEMPLATE_LOCATION, group_name))
    page_configs = {}
    for name, path in subfolders:
        compiled_folder = os.path.join(TEMPLATE_LOCATION, group_name, name)

        if not os.path.exists(compiled_folder):
            os.makedirs(compiled_folder)

        publish_images(group_name, name, path)

        pg_config = markdownparser.compile_markdown(name, path, group_name, compiled_folder)
        page_configs[name] = pg_config

    return page_configs
