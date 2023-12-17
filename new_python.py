new = open('./OSCP-techniques.md', 'r+')
output = open('OSCP-cheatsheet.md', 'w+')

all_lines = new.readlines()

# print(all_lines)

new_lines = ""
not_begun = 1
for i in range(0, len(all_lines)):
    if ("##" in all_lines[i]):
        new_lines += "\n```\n\n" + all_lines[i].strip() + "\n\n```\n"

    else:
        new_lines += all_lines[i].strip() + "\n"

print(new_lines)
              
output.write(new_lines)
