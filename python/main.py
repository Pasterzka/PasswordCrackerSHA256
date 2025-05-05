import asyncio
import sys
import time
import hashlib



# Generowanie kombinacji haseł
async def generateCombinations(queue, chars, lenght, password="", result = None):
    if len(password) == lenght:
        await queue.put(password)
        return
    
    for char in chars:
        if not result:
            passwordNew = password + char
            await generateCombinations(queue, chars, lenght, passwordNew, result)



# Wątek przeszukujący kolejkę w celu znalezienia złamanego hasła
async def thread(passwordHash, queue, result):
    while True:
        
        # pobranie nowego ciągu znaków
        passwordGet = await queue.get()
        found = await checkPassword(passwordHash, passwordGet)
        
        # sprawdzenie czy hasło zostało znalezione
        if found:
            result.append(found)
            queue.task_done()
            return
        
        queue.task_done()


# Funkcja sprawdza czy wygemerowane hasło jest takie samo jak zakodowane
async def checkPassword(passwordHash, passwordBruteforce):

    # zahaszowanie wygenerowanego hasła
    passwordBruteforceSHA256 = hashlib.sha256(passwordBruteforce.encode()).hexdigest()

    if passwordBruteforceSHA256 == passwordHash:
        return passwordBruteforce
    return None

# funkcja łamiąca hasło
async def bruteforce(passwordHash, lenght, chars):
    timeStart = time.time()
    queue = asyncio.Queue(maxsize=100000)
    result = []


    # 8 wątków
    threads = []
    for _ in range(8):
        threadTask = asyncio.create_task(thread(passwordHash, queue, result))
        threads.append(threadTask)
    combinationsTask = asyncio.create_task(generateCombinations(queue, chars, lenght, "", result))

    # sprawdza jakie wątki nie skończyły działania przed znalezieniem hasła
    done, pending = await asyncio.wait(
        [combinationsTask] + threads,
        return_when = asyncio.FIRST_COMPLETED
    )
    
    timeF = time.time() - timeStart

    for task in pending:
        task.cancel()

    if result:
        print(f"Znaleznione hasło: {result[0]}")
        print(f"Czas łamania hasła: {timeF:.2f} sekund.")
    else:
        print("Nie znaleziono hasła!")

# Funkcja pobiera argumenty i rozpoczyna działanie dekodujące
def main():
    if len(sys.argv) != 3:
        print("Użycie: python skrypt.py <HASH> <DŁUGOŚĆ>")
        sys.exit(1)
    
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

    passwordHash = sys.argv[1]
    lenght = int(sys.argv[2])

    asyncio.run(bruteforce(passwordHash, lenght, chars))

# Program
if __name__ == "__main__":
    main()