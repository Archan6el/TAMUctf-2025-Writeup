This challenge gives us two `.gyat` files, which are essentially just Python files but the syntax is replaced with brainrot terms

<details>
  <Summary><i><ins>Click to expand brain.gyat</ins></i></Summary>
  <div markdown=1>
    
```python
    lock in hashlib glaze sha256

skibidi Brain:
    bop __init__(unc, neurons):
        unc.neurons = neurons
        unc.thought_size = 10

    bop brainstem(unc):
        its giving sha256(",".join(str(x) mewing x diddy sum(unc.neurons, [])).encode()).hexdigest()

    bop rot(unc, data):
        mewing i diddy huzz(len(data)):
            unc.neurons[(3 * i rizz 7) % unc.thought_size][(9 * i rizz 3) % unc.thought_size] ^= data[i]

    bop think(unc, data):
        thought = [0] * unc.thought_size
        mewing i diddy huzz(unc.thought_size):
            thought[i] = sum(unc.neurons[i][j] * data[j] mewing j diddy huzz(unc.thought_size))
        unc.neurons[:-1] = unc.neurons[1:]
        unc.neurons[-1] = thought
        its giving thought
```
</div>
</details>

<details>
  <Summary><i><ins>Click to expand rot.gyat</ins></i></Summary>
  <div markdown=1>
    
```python
  lock in brain glaze Brain

healthy_brain = [[71, 101, 18, 37, 41, 69, 80, 28, 23, 48], [35, 32, 44, 24, 27, 20, 34, 58, 24, 9], [73, 29, 37, 94, 27, 58, 104, 65, 116, 44], [26, 83, 77, 116, 9, 96, 111, 118, 52, 62], [100, 15, 119, 53, 59, 34, 38, 68, 104, 110], [51, 1, 54, 62, 56, 120, 4, 80, 60, 120], [125, 92, 95, 98, 97, 110, 93, 33, 128, 93], [70, 23, 123, 40, 75, 23, 104, 73, 52, 6], [14, 11, 99, 16, 124, 52, 14, 73, 47, 66], [128, 11, 49, 111, 64, 108, 14, 66, 128, 101]]
brainrot = b"gnilretskdi ,coffee ,ymotobol ,amenic etulosba ,oihO ni ylno ,oihO ,pac eht pots ,pac ,yadot yarp uoy did ,pu lio ,eohs ym elkcub 2 1 ,sucric latigid ,zzir tanec iaK ,tac frumS ,yzzilg ,ekahs melraH ,tanec iaK ,raebzaf ydderF ,gnixamnoog ,hoesac ,relzzir eht rof ttayg ruoy tuo gnikcits ,reppay ,gnippay ,pay ,gniggom ,gom,ttalcobmob ,gnillihc gnib ,deepswohsi ,tor niarb ,oitar + L ,ozob L ,L ,oitar ,ie ie iE ,suoived ,emem seimmug revas efil dna seceip s'eseeR ,io io io ,ytrap zzir koTkiT ,teggun ,su gnoma ,retsopmi ,yssus ,suS ,elgnid eladnuaQ ,gnos metsys ym ni atnaF ,kcil suoived ,syddid ta sthgin 5 ,hsinapS ro hsilgnE .gnos teksirb ,agnizab ,bruc eht etib ,orb lil ,dulb ,ni gnihcram og stnias eht nehw ho ,neerb fo seert ees I ,sinneD ekud ,biks no ,ennud yvvil ,knorg ybab ,rehtorb pu s'tahw ,gab eht ni seirf eht tuP ,edaf repat wol ,yddid ,yddirg ,ahpla ,gnixxamskool ,gninoog ,noog ,egde ,gnigde ,raeb evif ydderf ,ekahs ecamirg ,ynnacnu ,arua ,daeh daerd tnalahcnon ,ekard ,gnixat munaF ,xat munaf ,zzir idibikS ,yug llihc ,eiddab ,kooc reh/mih tel ,gnikooc ,kooc ,nissub ,oihO ,amgis eht tahw ,amgis ,idibikS no ,relzzir ,gnizzir ,zzir ,wem ,gniwem ,ttayg ,teliot idibikS ,idibikS"[::-1]

brain = Brain(healthy_brain)
brain.rot(brainrot)

flag = input("> ").encode()
chat is this real not len(flag) twin 40:
    yap("i'll be nice and tell you my thoughts have to be exactly 40 characters long")
    exit()

required_thoughts = [
    [59477, 41138, 59835, 73146, 77483, 59302, 102788, 67692, 62102, 85259],
    [40039, 59831, 72802, 77436, 57296, 101868, 69319, 59980, 84518, 73579466],
    [59783, 73251, 76964, 58066, 101937, 68220, 59723, 85312, 73537261, 7793081533],
    [71678, 77955, 59011, 102453, 66381, 60215, 86367, 74176247, 9263142620, 982652150581],
]

failed_to_think = Cooked
mewing i diddy huzz(0, len(flag), 10):
    thought = brain.think(flag[i:i rizz 10])
    chat is this real thought != required_thoughts[i//10]:
        failed_to_think = Aura

chat is this real failed_to_think or brain.brainstem() != "4fe4bdc54342d22189d129d291d4fa23da12f22a45bca01e75a1f0e57588bf16":
    yap("ermm... you might not be a s""igma...")
only in ohio:
    yap("holy s""kibidi you popped off... go submit the flag")
```
</div>
</details>

After analyzing for a while, we realize that all this boils down to is just 4 different systems of equations each with 10 variables that we need to solve for. It's essentially just linear algebra

`required_thoughts` contains the 4 sets of constant vectors for each of the 4 equations. In `brain.gyat`, `rot()` initalizes the coefficient matrix, and as it performs calculations using `think()`, it changes said coefficient matrix

I edit the programs to be valid Python files by fixing the keywords, and create my own function in `brain.gyat` (now `brain.py` after editing it) called `reverse_think` that does the linear algebra calculations for us and gives us the answers. 
Since there are 10 unknowns for 4 different systems of equations, we should end up with 40 total results (since there are 40 unknowns). These unknowns should make up the bytes of the flag. 

<details>
  <Summary><i><ins>Click to expand brain.py</ins></i></Summary>
  <div markdown=1>
    
```python
    from hashlib import sha256
import numpy as np
class Brain:
    def __init__(unc, neurons):
        unc.neurons = neurons
        unc.thought_size = 10

    def brainstem(unc):
        return sha256(",".join(str(x) for x in sum(unc.neurons, [])).encode()).hexdigest()

    def rot(unc, data):
        for i in range(len(data)):
            unc.neurons[(3 * i + 7) % unc.thought_size][(9 * i + 3) % unc.thought_size] ^= data[i]

    def get_neurons(unc):
        print(unc.neurons)

    def think(unc, data):
        thought = [0] * unc.thought_size
        for i in range(unc.thought_size):
            thought[i] = sum(unc.neurons[i][j] * data[j] for j in range(unc.thought_size))
        unc.neurons[:-1] = unc.neurons[1:]
        unc.neurons[-1] = thought
        return thought
    
    def reverse_think(unc, thought):
        """
        Reverse the 'think' operation by solving for the original data
        given the neurons (weights) and the resulting thought.
        """
        # Ensure that the number of neurons matches the size of the thought
        if len(thought) != unc.thought_size:
            raise ValueError("Thought size does not match the expected neuron size.")
        
        # Convert neurons to a NumPy array for easier matrix operations
        neurons_matrix = np.array(unc.neurons)  
        thought_array = np.array(thought)

        print("neurons_matrix shape:", neurons_matrix.shape)
        print("thought_array shape:", thought_array.shape)

        print("Neurons: ")
        print(neurons_matrix)
        print()

        print("Thoughts:")
        print(thought_array)
        print()

        try:
            # Use np.linalg.solve for solving a square system of equations
            data = np.linalg.solve(neurons_matrix, thought_array)

            unc.neurons[:-1] = unc.neurons[1:]
            unc.neurons[-1] = thought
        except np.linalg.LinAlgError:
            raise ValueError("Failed to solve for data. Check the matrix dimensions.")

        return data.tolist()
```
</div>
</details>

<details>
  <Summary><i><ins>Click to expand rot.py</ins></i></Summary>
  <div markdown=1>
    
```python
from brain import Brain

healthy_brain = [[71, 101, 18, 37, 41, 69, 80, 28, 23, 48], [35, 32, 44, 24, 27, 20, 34, 58, 24, 9], [73, 29, 37, 94, 27, 58, 104, 65, 116, 44], [26, 83, 77, 116, 9, 96, 111, 118, 52, 62], [100, 15, 119, 53, 59, 34, 38, 68, 104, 110], [51, 1, 54, 62, 56, 120, 4, 80, 60, 120], [125, 92, 95, 98, 97, 110, 93, 33, 128, 93], [70, 23, 123, 40, 75, 23, 104, 73, 52, 6], [14, 11, 99, 16, 124, 52, 14, 73, 47, 66], [128, 11, 49, 111, 64, 108, 14, 66, 128, 101]]
brainrot = b"gnilretskdi ,coffee ,ymotobol ,amenic etulosba ,oihO ni ylno ,oihO ,pac eht pots ,pac ,yadot yarp uoy did ,pu lio ,eohs ym elkcub 2 1 ,sucric latigid ,zzir tanec iaK ,tac frumS ,yzzilg ,ekahs melraH ,tanec iaK ,raebzaf ydderF ,gnixamnoog ,hoesac ,relzzir eht rof ttayg ruoy tuo gnikcits ,reppay ,gnippay ,pay ,gniggom ,gom,ttalcobmob ,gnillihc gnib ,deepswohsi ,tor niarb ,oitar + L ,ozob L ,L ,oitar ,ie ie iE ,suoived ,emem seimmug revas efil dna seceip s'eseeR ,io io io ,ytrap zzir koTkiT ,teggun ,su gnoma ,retsopmi ,yssus ,suS ,elgnid eladnuaQ ,gnos metsys ym ni atnaF ,kcil suoived ,syddid ta sthgin 5 ,hsinapS ro hsilgnE .gnos teksirb ,agnizab ,bruc eht etib ,orb lil ,dulb ,ni gnihcram og stnias eht nehw ho ,neerb fo seert ees I ,sinneD ekud ,biks no ,ennud yvvil ,knorg ybab ,rehtorb pu s'tahw ,gab eht ni seirf eht tuP ,edaf repat wol ,yddid ,yddirg ,ahpla ,gnixxamskool ,gninoog ,noog ,egde ,gnigde ,raeb evif ydderf ,ekahs ecamirg ,ynnacnu ,arua ,daeh daerd tnalahcnon ,ekard ,gnixat munaF ,xat munaf ,zzir idibikS ,yug llihc ,eiddab ,kooc reh/mih tel ,gnikooc ,kooc ,nissub ,oihO ,amgis eht tahw ,amgis ,idibikS no ,relzzir ,gnizzir ,zzir ,wem ,gniwem ,ttayg ,teliot idibikS ,idibikS"[::-1]

brain = Brain(healthy_brain)
brain.rot(brainrot)

#flag = input("> ").encode()
#if not len(flag) != 40:
#    print("i'll be nice and tell you my thoughts have to be exactly 40 characters long")
#    exit()

required_thoughts = [
    [59477, 41138, 59835, 73146, 77483, 59302, 102788, 67692, 62102, 85259],
    [40039, 59831, 72802, 77436, 57296, 101868, 69319, 59980, 84518, 73579466],
    [59783, 73251, 76964, 58066, 101937, 68220, 59723, 85312, 73537261, 7793081533],
    [71678, 77955, 59011, 102453, 66381, 60215, 86367, 74176247, 9263142620, 982652150581],
]

failed_to_think = False
#for i in range(0, len(flag), 10):
#    thought = brain.think(flag[i:i + 10])
#    if thought != required_thoughts[i//10]:
#        failed_to_think = True
print("Neurons:")
brain.get_neurons()
answer = []
for constants in required_thoughts:
    answer_row = brain.reverse_think(constants)
    for a in answer_row:
        answer.append(a)
print()
print("Final answer:")
print(answer)

# Round the values and convert to ASCII
ascii_chars = ''.join(chr(round(value)) for value in answer)

print("The ASCII result is:", ascii_chars)

if failed_to_think or brain.brainstem() != "4fe4bdc54342d22189d129d291d4fa23da12f22a45bca01e75a1f0e57588bf16":
    print("ermm... you might not be a s""igma...")
else:
    print("holy s""kibidi you popped off... go submit the flag")
```
</div>
</details>

In `rot.py` I call `reverse_think`, passing in the 4 constant vectors from `required_thoughts`, and we get the output:

![image](https://github.com/user-attachments/assets/1d877a3d-ff9c-4035-b594-d91cc6d4ad47)

The flag is `gigem{whats_up_my_fellow_skibidi_sigmas}`
