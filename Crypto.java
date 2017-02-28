package csc_650_p1;

import java.util.Arrays;
import java.lang.Math;
import java.util.Random;

public class Crypto {

	int[] DES(int[] plaintext, int[] key) throws InvalidDESArgumentsException {
		if (plaintext.length != 64) {
			throw new InvalidDESArgumentsException("Plaintext must be 64 bits");
		} else if (key.length != 64) {
			throw new InvalidDESArgumentsException("Key must be 64 bits");
		}
		int[] initialMessagePermutation = this.getInitialMessagePermutation(plaintext);
		int[] permutedKey = this.permuteKey(key);
		int[] keyInitialLeft = this.bitsInRange(permutedKey, 0, 27);
		int[] keyInitialRight = this.bitsInRange(permutedKey, 28, 55);
		int[][] final_keys = this.getDESRoundKeys(keyInitialLeft, keyInitialRight);
		int[] nextLHS = this.bitsInRange(initialMessagePermutation, 0, 31);
		int[] nextRHS = this.bitsInRange(initialMessagePermutation, 32, 63);

		for (int i = 0; i < 16; i++) { // main DES loop
			int[] previousLHS = nextLHS.clone();
			int[] previousRHS = nextRHS.clone();
			nextLHS = previousRHS.clone();
			nextRHS = this.xor(previousLHS, this.desMangle(final_keys[i], previousRHS));
		}
		int [] cipherText = this.finalMessagePermutation(nextLHS, nextRHS);
		return cipherText;
	}

	private int[] finalMessagePermutation(int[] finalLHS, int[] finalRHS) {
		int[] concatInvertedSides = this.concat(finalRHS, finalLHS);
		int [] result = new int[64];
		int[] permutationMap = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
				62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34,
				2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
		for (int i=0; i<permutationMap.length; i++){
			result[i] = concatInvertedSides[permutationMap[i]-1];
		}
		return result;
	}

	private int[] desMangle(int[] key, int[] rhs) {
		int[] mangledRHS = this.desMangleSelectionFunctionE(rhs);
		int[] MangledRhsXorKey = this.xor(mangledRHS, key);
		int[] sBoxMangledRhs = this.runSBoxes(MangledRhsXorKey);
		int[] finalPermutedResult = this.desMangleFinalPermutation(sBoxMangledRhs);
		return finalPermutedResult;
	}

	public int[] desMangleSelectionFunctionE(int[] rhs) {
		int[] result = new int[48];
		result[0] = rhs[31];
		result[47] = rhs[0];
		int nextValueIndex = 0;
		for (int nextResultIndex = 1; nextResultIndex < 47; nextResultIndex++) {
			for (int i = 0; i < 5 && nextResultIndex < 47; i++) {
				result[nextResultIndex] = rhs[nextValueIndex];
				nextValueIndex++;
				nextResultIndex++;
			}
			if (nextResultIndex == 47) {
				break;
			}
			nextValueIndex--;
			result[nextResultIndex] = rhs[nextValueIndex - 1];
		}

		return result;
	}

	public int[] desMangleFinalPermutation(int[] input) {
		int[] result = new int[32];
		int[] permutationMap = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3,
				9, 19, 13, 30, 6, 22, 11, 4, 25 };
		for (int i = 0; i < 32; i++) {
			result[i] = input[permutationMap[i]-1];
		}
		return result;
	}

	public int[] runSBoxes(int[] rhs) {
		int[][] bitGroups = this.get6BitGroups(rhs);
		int[][] initialSBox = this.getSBox(0);
		int[] result = this.computeSBoxResult(bitGroups[0], initialSBox);
		for (int i = 1; i < 8; i++) {
			int[][] sBox = this.getSBox(i);
			result = this.concat(result, this.computeSBoxResult(bitGroups[i], sBox));
		}
		return result;
	}

	public int[] computeSBoxResult(int[] group, int[][] sBox) {
		int result[] = new int[4];
		int rowBits[] = { group[0], group[5] };
		int colBits[] = { group[1], group[2], group[3], group[4] };
		int row = this.binArrToInt(rowBits);
		int col = this.binArrToInt(colBits);
		result = this.intToBinArr(sBox[row][col]);
		return result;
	}

	public int[][] get6BitGroups(int[] initial) {
		int[][] result = new int[8][6];
		for (int i = 0; i < 8; i++) {
			result[i] = this.bitsInRange(initial, i * 6, i * 6 + 5);
		}
		return result;
	}

	// doesn't account for overflow
	public int binArrToInt(int[] binArr) {
		int result = 0;
		for (int i = binArr.length - 1; i >= 0; i--) {
			result += binArr[i] * ((int) Math.pow(2, binArr.length - 1 - i));
		}
		return result;
	}

	// assume we're only going to get max int of 15 (4 bits)
	public int[] intToBinArr(int arg) {
		int[] result = new int[4];
		int tempPrev = arg;
		for (int i = 3; tempPrev != 0; i--) {
			int temp = tempPrev - ((int) Math.pow(2, i));
			if (temp >= 0) {
				result[3 - i] = 1;
				tempPrev = temp;
			} else {
				temp = arg;
			}
		}
		return result;
	}

	// assumes binary int array
	public int[] xor(int[] op1, int[] op2) {
		int[] result = new int[op1.length];
		for (int i = 0; i < op1.length; i++) {
			if (op1[i] == op2[i]) {
				result[i] = 0;
			} else {
				result[i] = 1;
			}
		}
		return result;
	}

	private int[] getInitialMessagePermutation(int[] plainText) {
		int[][] initialMatrix = this.arrayToMatrix(plainText, 8);
		System.out.println(Arrays.deepToString(initialMatrix));
		int[][] permutedMatrix = new int[8][8];
		for (int row = 0; row < 8; row++) {
			for (int col = 0; col < 8; col++) {
				if ((col + 1) % 2 == 0) {
					// even columns go to the first 4 rows of permutedMatrix
					// each row of initialMatrix goes to the (7-row)th column of
					// permutedMatrix
					permutedMatrix[((col + 1) / 2) - 1][7 - row] = initialMatrix[row][col];
				} else { // odd columns
							// the initial odd cols 0,2,4,6 are mapped to -->
							// permuted cols 4,5,6,7
							// ((oddCol+2)/2)+3 gives the column in the permuted
							// matrix
					permutedMatrix[((col + 2) / 2) + 3][7 - row] = initialMatrix[row][col];
				}
			}
		}
		return this.matrixToArray(permutedMatrix);
	}

	public int[] permuteKey(int[] k) {
		int[] kNoParity = this.removeKeyParityBits(k);
		int[][] kArrInitial = this.arrayToMatrix(kNoParity, 7);
		int[][] kArrFinal = new int[8][7];
		int[] leftOver1 = new int[4];

		// The first 4 rows of the final matrix are derived from the first 4
		// columns of the initial matrix
		// Iterate through the columns of the initial matrix
		for (int col = 0; col < 4; col++) {
			// Walk backwards from the last row of this column
			// The last row element will become the first column element in the
			// final matrix
			// Exclude the first (col+1) rows of the initial matrix to be used
			// as "leftover values" for the next iteration
			for (int row = 7; row >= col + 1; row--) {
				kArrFinal[col][7 - row + col] = kArrInitial[row][col];
			}
			if (col > 0) { // the first iteration doesn't have leftovers
				// The values leftover from the last iteration become the first
				// 'i' columns of the target row
				for (int i = 0; i < col; i++) {
					kArrFinal[col][i] = leftOver1[i];
				}
			}
			// save the first 'col' elements as leftovers
			for (int row = col; row >= 0; row--) {
				leftOver1[col - row] = kArrInitial[row][col];
			}
		}
		int[] leftOver2 = new int[4];
		// Now do a similar operation on the last 3 columns (indexed from the
		// last column of the initial matrix)
		for (int col = 6; col > 3; col--) {
			// Walk backwards from the row of this column
			// Use some algebra to find that the row of kArrFinal=(-col+10)
			for (int row = 7; row > 6 - col; row--) {
				kArrFinal[-col + 10][7 - row + 6 - col] = kArrInitial[row][col];
			}
			if (col < 6) { // sixth column doesn't have leftovers to assign
				for (int i = 0; i < 6 - col; i++) {
					kArrFinal[-col + 10][i] = leftOver2[i];
				}
			}

			// save the first '6-col' elements as leftovers
			for (int row = 6 - col; row >= 0; row--) {
				leftOver2[6 - row - col] = kArrInitial[row][col];
			}
		}

		// THE FINAL ROW!! it feels good to be done... this wasn't fun to
		// implement :(
		// The final row is just leftOver2 concatenated with leftOver1:
		for (int i = 0; i < 3; i++) {
			kArrFinal[7][i] = leftOver2[i];
		}

		for (int i = 0; i < 4; i++) {
			kArrFinal[7][i + 3] = leftOver1[i];
		}

		return this.matrixToArray(kArrFinal);
	}

	private int[][] getDESRoundKeys(int[] initKeyL, int[] initKeyR) {
		int[][] result = new int[16][48];
		int[][] cKeys = this.getBitShiftKeys(initKeyL);
		int[][] dKeys = this.getBitShiftKeys(initKeyR);
		for (int i = 0; i < 16; i++) {
			result[i] = permutedBitShiftKey(cKeys[i], dKeys[i]);
		}
		return result;
	}

	private int[] permutedBitShiftKey(int[] cKey, int[] dKey) {
		int[] permuteMap = { 13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40,
				51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };
		int[] concatKeys = this.concat(cKey, dKey);
		int[] result = new int[48];
		for (int i = 0; i < permuteMap.length; i++) {
			result[i] = concatKeys[permuteMap[i]];
		}
		return result;

	}

	private int[] concat(int[] a, int[] b) {
		int[] result = new int[a.length + b.length];
		for (int i = 0; i < a.length; i++) {
			result[i] = a[i];
		}
		for (int i = 0; i < b.length; i++) {
			result[i + a.length] = b[i];
		}
		return result;
	}

	private int[][] getBitShiftKeys(int[] keySide) {
		int[][] result = new int[16][28];
		int[] lastK = keySide.clone();
		for (int i = 0; i < 16; i++) {
			if (i == 0 || i == 1 || i == 8 || i == 15) {
				lastK = this.leftShiftOnce(lastK);
			} else {
				lastK = this.leftShiftTwice(lastK);
			}
			result[i] = lastK;
		}
		return result;
	}

	private int[] leftShiftTwice(int[] keySide) {
		int[] firstShift = this.leftShiftOnce(keySide);
		return this.leftShiftOnce(firstShift);
	}

	private int[] leftShiftOnce(int[] keySide) {
		int firstBit = keySide[0];
		int[] result = new int[keySide.length];
		for (int i = 1; i < keySide.length; i++) {
			result[i - 1] = keySide[i];
		}
		result[keySide.length - 1] = firstBit;
		return result;
	}

	private int[] bitsInRange(int[] a, int low, int high) {
		int[] res = new int[high - low + 1];
		for (int i = low; i <= high; i++) {
			res[i - low] = a[i];
		}
		return res;
	}

	private int[] removeLeftKeyThrowawayBits(int[] kLeft) {
		int[] kResult = new int[24];
		return kResult;

	}

	private int[] removeKeyParityBits(int[] k) {
		int[] k_result = new int[56];
		int next_k_res = 0;
		for (int i = 0; i < 64; i++) {
			if ((i + 1) % 8 != 0) {
				k_result[next_k_res] = k[i];
				next_k_res++;
			}
		}
		return k_result;
	}

	private int[][] arrayToMatrix(int[] a, int rowLen) {
		if (a.length % rowLen != 0) {
			System.out.println("Array length is not divisible by rowLen arg, this will result in an error.");
		}
		int numRows = a.length / rowLen;
		int[][] m = new int[numRows][rowLen];
		for (int row = 0; row < numRows; row++) {
			for (int col = 0; col < rowLen; col++) {
				m[row][col] = a[row * rowLen + col];
			}
		}
		return m;
	}

	// assumes the matrix isn't ragged
	public int[] matrixToArray(int[][] m) {
		int[] a = new int[m.length * m[0].length];
		for (int row = 0; row < m.length; row++) {
			for (int col = 0; col < m[0].length; col++) {
				a[row * m[0].length + col] = m[row][col];
			}
		}
		return a;
	}

	public int[][] getSBox(int iteration) {
		int[][][] sBoxes = {
				{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
						{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
						{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
						{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
				{ { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
						{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
						{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
						{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
				{ { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
						{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
						{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
						{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
				{ { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
						{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
						{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
						{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
				{ { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
						{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
						{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
						{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
				{ { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
						{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
						{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
						{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
				{ { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
						{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
						{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
						{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
				{ { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
						{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
						{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
						{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } };
		return sBoxes[iteration];
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Crypto crypto = new Crypto();
		int[] plaintext = { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
			     0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
			     0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1,
			     1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};

		int[] key = { 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
			     0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0,
			     1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1,
			     1, 1, 1, 1, 1, 0, 0, 0, 1 };
		int[] cipherText = new int[64]; 
		try{
			 cipherText = crypto.DES(plaintext, key);
		 }
		 catch(InvalidDESArgumentsException e){
			 System.out.println(e.getMessage());
		 }
		 System.out.println(Arrays.toString(cipherText));

	}

}
