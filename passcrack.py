# Simple email script meant for a gmail sender
def sendEmail(fromGmail, fromPwd, toEmails, subject, body):
    # Import smtp library
    import smtplib

    # Initialize vars
    usr = fromGmail
    pwd = fromPwd
    FROM = usr
    TO = toEmails if type(toEmails) is list else [toEmails]
    SUBJECT = subject
    TEXT = body

    # Prepare and attempt to send email message
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(usr, pwd)
        server.sendmail(FROM, TO, message)
        server.close()
        print "Successfully sent the email"
    except:
        print "Failed to send the email"

# Capitalize every other letter in a string
# idx == 0 -> start with first letter, idx == 1 -> start with second letter
def capEveryOther(word, idx):
    ret = ""
    for i in range(0, len(word)):
        if (i + idx) % 2 == 0:
            ret += word[i].upper()
        else:
            ret += word[i].lower()
    return ret

# Perform character-to-number/symbol substitution
def charSubst(word, old, new):
    tmp = word.replace(old.lower(), new)
    ret = tmp.replace(old.upper(), new)
    return ret

# Password cracking script
import sys
import time
import crypt
from itertools import product

if len(sys.argv) != 5:
    print "Usage: {} dictionary.txt alg salt hash".format(sys.argv[0])
else:
    # Read in arguments
    dct = str(sys.argv[1])
    alg = str(sys.argv[2])
    slt = str(sys.argv[3])
    hsh = str(sys.argv[4])

    # Declare variables
    startTime = time.time()
    MAX_LEVEL = 6
    hashFound = False
    hashGuess = ""
    passGuess = ""
    formattedSalt = ""
    temp = ""
    entryPerms = []
    level = 1
    i = -1
    j = 0
    alg = int(alg)
    levelOneT = 0
    levelTwoT = 0
    levelThreeT = 0
    levelFourT = 0
    levelFiveT = 0
    emailTimeStr = ""
    numSubChars = ["l", "e", "a", "s", "b", "t", "o"]
    symSubChars = ["i", "a", "v", "s", "c"]
    specChars = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", ",", "/", "\\", "?", "'", "<", ">", ";", ":", "~", "[", "]", "{", "}", "|"]
    bruteChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,!?@#$%^&*()=+'\"/\;:[]{}|`~<> "

    # Create a formatted salt based on the input
    # If alg does not equal 1, 5, or 6, assumed to be DES
    if alg == 1 or alg == 5 or alg == 6:
        formattedSalt = "$" + str(alg) + "$" + str(slt) + "$"
    else:
        formattedSalt = str(slt)
        alg = 0

    levelOneF = "level-one-" + str(alg) + ".txt"
    levelTwoF = "level-two-" + str(alg) + ".txt"
    levelThreeF = "level-three-" + str(alg) + ".txt"
    levelFourF = "level-four-" + str(alg) + ".txt"
    refFile = open(dct, "r")
    modFile = open(levelOneF, "w")
    
    print "Time elapsed (in seconds) for:\n"
    emailTimeStr += "Time elapsed (in seconds) for:\n"
    
    # Perform password guessing logic based on dictionary entries, substitutions, and other various methods
    while hashGuess != hsh:
        line = refFile.readline()
        if line == "":
            level += 1
            if refFile is not None:
                refFile.close()
            if modFile is not None:
                modFile.close()
            if level == 2:
                refFile = open(levelOneF, "r")
                modFile = open(levelTwoF, "w")
                levelOneT = time.time()
                print "Level x: {} \n".format(levelOneT - startTime)
                emailTimeStr += "Level 1: {} \n".format(levelOneT - startTime)
            elif level == 3:
                refFile = open(levelTwoF, "r")
                modFile = open(levelThreeF, "w")
                levelTwoT = time.time()
                print "Level 2: {} \n".format(levelTwoT - levelOneT)
                emailTimeStr += "Level 2: {} \n".format(levelTwoT - levelOneT)
            elif level == 4:
                refFile = open(levelThreeF, "r")
                modFile = open(levelFourF, "w")
                levelThreeT = time.time()
                print "Level 3: {} \n".format(levelThreeT - levelTwoT)
                emailTimeStr += "Level 3: {} \n".format(levelThreeT - levelTwoT)
            elif level == 5:
                refFile = open(levelFourF, "r")
                modFile = None
                levelFourT = time.time()
                print "Level 4: {} \n".format(levelFourT - levelThreeT)
                emailTimeStr += "Level 4: {} \n".format(levelFourT - levelThreeT)
            elif level == 6:
                refFile = None
                modFile = None
                levelFiveT = time.time()
                print "Level 5: {} \n".format(levelFiveT - levelFourT)
                emailTimeStr += "Level 5: {} \n".format(levelFiveT - levelFourT)

            if refFile is not None:
                line = refFile.readline()
        line = line.rstrip("\n")
        
        # Use the level value to determine what type of modification to make to base dictVals
        # Higher the level == more complicated/time-consuming attempts.
        # In principle, quicker/easier passwords will be attempted first

        # Set temp to current entry
        temp = line
        entryLen = len(temp)
        entryPerms = []
        
        # Pad shorter entries with a common "123..."
        if entryLen < 6:
            for j in range(1, 7 - entryLen):
                temp += str(j)

        if level == 1:
            ''' Level 1: (Letter Case) For each dictionary entry try:
                - all lower case
                - all upper case
                - first letter capitalized
                - every other letter capitalized (starting with the first one)
                - every other letter capitalized (starting with the second one)
            '''
            modFile.write(temp.lower() + "\n")
            entryPerms.append(temp.lower())
            modFile.write(temp.upper() + "\n")
            entryPerms.append(temp.upper())
            modFile.write(temp.capitalize() + "\n")
            entryPerms.append(temp.capitalize())
            modFile.write(capEveryOther(temp, 0) + "\n")
            entryPerms.append(capEveryOther(temp, 0))
            modFile.write(capEveryOther(temp, 1) + "\n")
            entryPerms.append(capEveryOther(temp, 1)) 
        elif level == 2:
            ''' Level 2: (Number Substitution) For each value from level 1, try:
                - 1 for l
                - 3 for e
                - 4 for a
                - 5 for s
                - 6 for b
                - 7 for t
                - 0 for o
                - Combinations of each of the above
            '''
            modFile.write(temp + "\n")
            entryPerms.append(temp)
            
            # Count number of chars that can be substituted
            charCount = 0
            subsMade = 0
            tmpSub = ""
            for j in range(0, len(numSubChars)):
                if numSubChars[j] in temp:
                    charCount += 1

            for j in range(0, charCount):
                subsMade = 0
                tmpSub = temp
                
                if "l" in temp or "L" in temp:
                    tmpSub = charSubst(tmpSub, "l", "1")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "e" in temp or "E" in temp:
                    tmpSub = charSubst(tmpSub, "e", "3")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "a" in temp or "A" in temp:
                    tmpSub = charSubst(tmpSub, "a", "4")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "s" in temp or "S" in temp:
                    tmpSub = charSubst(tmpSub, "s", "5")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "b" in temp or "B" in temp:
                    tmpSub = charSubst(tmpSub, "b", "6")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "t" in temp or "T" in temp:
                    tmpSub = charSubst(tmpSub, "t", "7")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "o" in temp or "O" in temp:
                    tmpSub = charSubst(tmpSub, "o", "0")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
        elif level == 3:
            ''' Level 3: (Ordering Permutation) For each value from level 2, try:
                - Reversing the entry
            '''
            modFile.write(temp + "\n")
            entryPerms.append(temp)
            modFile.write(temp[::-1] + "\n")
            entryPerms.append(temp[::-1])
        elif level == 4:
            ''' Level 4: (Symbol Substitution) For each value from level 3, try:
                - ! for i
                - @ for a
                - ^ for v
                - $ for s
                - ( for c
                - Combinations of each of the above
            '''
            modFile.write(temp + "\n")
            entryPerms.append(temp)

            #Count number of chars that can be substituted
            charCount = 0
            subsMade = 0
            tmpSub = ""
            for j in range(0, len(symSubChars)):
                if symSubChars[j] in temp:
                    charCount += 1

            for j in range(0, charCount):
                subsMade = 0
                tmpSub = temp
                
                if "i" in temp or "I" in temp:
                    tmpSub = charSubst(tmpSub, "i", "!")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "a" in temp or "A" in temp:
                    tmpSub = charSubst(tmpSub, "a", "@")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "v" in temp or "V" in temp:
                    tmpSub = charSubst(tmpSub, "v", "^")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "s" in temp or "S" in temp:
                    tmpSub = charSubst(tmpSub, "s", "$")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
                if "c" in temp or "C" in temp:
                    tmpSub = charSubst(tmpSub, "c", "(")
                    subsMade += 1
                    if subsMade == j + 1:
                        modFile.write(tmpSub + "\n")
                        entryPerms.append(tmpSub)
                        subsMade = 0
                        tmpSub = temp
        elif level == 5:
            ''' Level 5: (Special Characters) For each value of level 4, try:
                - Inserting "common" special characters for each position:
                    ' ', '-', '_', '.'
                - Inserting "uncommon" special characters at the beginning, end, and both:
                    '!', '@','#', '$', '%', '^', '&', '*', '(', ')', '+', '=', ',', '/', '?',
                    '\', '`', '<', '>', ';', ':', '~', '[', ']', '{', '}', '|'
            '''
            entryPerms.append(temp)
            
            for j in range(0, entryLen + 1):
                entryPerms.append(temp[:j] + " " + temp[j:])
                entryPerms.append(temp[:j] + "-" + temp[j:])
                entryPerms.append(temp[:j] + "_" + temp[j:])
                entryPerms.append(temp[:j] + "." + temp[j:])
                
            for j in range(0, len(specChars)):
                entryPerms.append(specChars[j] + temp)
                entryPerms.append(temp + specChars[j])
                entryPerms.append(specChars[j] + temp + specChars[j])
        elif level == 6:
            ''' Level 6: (Brute Force) If the code reaches this point, begin performing a brute
                force search of all possible combinations in "bruteChars"
                    
            '''
            for j in range(6, 15):
                print "*********************Brute Char Count: " + str(j) + "\n"
                for brPass in product(bruteChars, repeat=j):
                    passGuess = "".join(brPass)
                    hashGuess = crypt.crypt(passGuess, formattedSalt)
                    if hashGuess == formattedSalt + hsh:
                        hashFound = True
                        print passGuess
                        emailTimeStr += "Level 6 \n"
                        break
                if hashFound == True:
                     break
            if hashFound == False:
                level = 7
            
        # Check if control just came from level 6
        if hashFound == True or level == 7:
            break
    
        # Perform the crypt function with the corresponding guess and salt
        for j in range(0, len(entryPerms)):
            # Encrypt
            passGuess = entryPerms[j]
            hashGuess = crypt.crypt(passGuess, formattedSalt)
            
            # Compare the hashes
            if hashGuess == formattedSalt + hsh:
                hashFound = True
                if level == 1:
                    print "Level 1: {} \n".format(time.time() - startTime)
                    emailTimeStr += "Level 1: {} \n".format(time.time() - startTime)
                elif level == 2:
                    print "Level 2: {} \n".format(time.time() - levelOneT)
                    emailTimeStr += "Level 2: {} \n".format(time.time() - levelOneT)
                elif level == 3:
                    print "Level 3: {} \n".format(time.time() - levelTwoT)
                    emailTimeStr += "Level 3: {} \n".format(time.time() - levelTwoT)
                elif level == 4:
                    print "Level 4: {} \n".format(time.time() - levelThreeT)
                    emailTimeStr += "Level 4: {} \n".format(time.time() - levelThreeT)
                elif level == 5:
                    print "Level 5: {} \n".format(time.time() - levelFourT)
                    emailTimeStr += "Level 5: {} \n".format(time.time() - levelFourT)
                break

        # Check if the correct password was found
        if hashFound == True:
            break
            
    # Make sure the program broke out of the while loop because the correct password was found
    if hashFound == True:
        # Print the hash/password to the console
        print "Password for hash {} found: {}".format(formattedSalt + hsh, passGuess)
        
        # Print the hash/password to a text file
        recF = open("crackedpass.txt", "a")
        recF.write("Hash: {} Pass: {}".format(formattedSalt + hsh, passGuess))
        recF.write("\n")
        recF.close()
        
        # Print the hash/password to an email
        emailTimeStr += "Password for hash {} found: {}".format(formattedSalt + hsh, passGuess)
        sendEmail("a@b.com", "password", "y@z.com", "STATUS: Password Found", emailTimeStr)
    elif level > MAX_LEVEL:
        # Print the level exceeded message to the console
        print "Level value exceeded!"

        # Print the level exceeded message to an email
        emailTimeStr += "Level value exceeded!"
        sendEmail("a@b.com", "password", "y@z.com", "STATUS: Level Exceeded", emailTimeStr)
    else:
        # Print the unexpected error message to the console
        print "An unexpected error occurred somewhere (i.e. you're SOL)"

        # Print the unexpected error message to an email
        emailTimeStr += "An unexpected error occurred somewhere (i.e. you're SOL)"
        sendEmail("a@b.comm", "password", "y@z.com", "STATUS: Unexpected Error", emailTimeStr)
