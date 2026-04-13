path = r"C:\Users\user\.antigravity\liences tool\saas-admin\src\app\data-management\page.tsx"
content = open(path, 'r', encoding='utf-8').read()

# Fix the key prop placement - it's on a separate line outside the JSX tag
old = '''                           <div\r
                             key={entry.name}\r
                             className={`cursor-pointer'''

new = '''                           <div\r
                             key={entry.name}
                             className={`cursor-pointer'''

# Actually the issue is the CRLF inconsistency. Let's fix the key issue properly
# The div has key as a separate line which is correct JSX, but let's check if it's inside the tag
old2 = '                           <div\r\n                             key={entry.name}\r\n                             className'
new2 = '                           <div\r\n                             key={entry.name}\r\n                             className'

print("key line context:")
idx = content.find('key={entry.name}')
if idx >= 0:
    print(repr(content[idx-60:idx+100]))
else:
    print("NOT FOUND")
