#!/usr/bin/env python3
import re
import sys
import os
from pathlib import Path

class Register:
    def __init__(self, reg, constraint, variable):
        self.reg = reg          # e.g. 'x7'
        self.constraint = constraint  # e.g. '=&r'
        self.variable = variable      # e.g. '_a->out_2_x7[_i]'
    def is_address(self):
        """Check if this is an address reference."""
        return self.variable.startswith('&')
    def is_trashed(self):
        """Check if this register is trashed."""
        return self.variable.startswith('trashed')

class AsmVectorizer:
    def __init__(self):
        # Conversion rules for RISC-V instructions
        self.conversions = {
            r'lb\s+(%\[x\d+\]),\s*0': r'vle8.v \1,',
            r'sb\s+(%\[x\d+\]),\s*0': r'vse8.v \1,',
            r'lh\s+(%\[x\d+\]),\s*0': r'vle16.v \1,',
            r'sh\s+(%\[x\d+\]),\s*0': r'vse16.v \1,',
            r'lw\s+(%\[x\d+\]),\s*0': r'vle32.v \1,',
            r'sw\s+(%\[x\d+\]),\s*0': r'vse32.v \1,',
            r'ld\s+(%\[x\d+\]),\s*0': r'vle64.v \1,',
            r'sd\s+(%\[x\d+\]),\s*0': r'vse64.v \1,',
            r'add\s+(%\[x\d+\])': r'vadd.vv \1',
            r'sub\s+(%\[x\d+\])': r'vsub.vv \1',
            r'xor\s+(%\[x\d+\])': r'vxor.vv \1',
            r'and\s+(%\[x\d+\])': r'vand.vv \1',
            r'or\s+(%\[x\d+\])': r'vor.vv \1'
        }

        # Vector initialization template
        self.vector_init = '"vsetivli x0, 1, e32, m1\\n"\n'

    def parse_asm_outputs(self, output_str):
        """Parse ASM output constraints into a list of Register objects.
        
        Example inputs: 
        ':[x7] "=&r" (_a->out_2_x7[_i])'
        ':[x5] "=&r" ((int)(foo->bar))'
        """
        outputs = []
        
        # Remove leading ':' if present
        output_str = output_str.lstrip(':')
        
        # Find all register and constraint pairs
        reg_constraint_pattern = r'\[([^\]]+)\]\s*"([^"]+)"'
        
        pos = 0
        for match in re.finditer(reg_constraint_pattern, output_str):
            reg = match.group(1)        # x7
            constraint = match.group(2)  # =&r
            
            # Find the start of the variable (first opening parenthesis after the constraint)
            var_start = output_str.find('(', match.end())
            if var_start == -1:
                continue
                
            # Find the matching closing parenthesis
            paren_count = 1
            var_end = var_start + 1
            
            while paren_count > 0 and var_end < len(output_str):
                if output_str[var_end] == '(':
                    paren_count += 1
                elif output_str[var_end] == ')':
                    paren_count -= 1
                var_end += 1
                
            if paren_count == 0:
                # Extract variable without the outermost parentheses
                variable = output_str[var_start + 1:var_end - 1]
                outputs.append(Register(reg, constraint, variable))
    
        return outputs

    def output_decls(self, outputs):
        decls = ""
        for output in outputs:
            decls = decls + f"vint32m1_t {output.reg}"
            if not output.is_trashed():
                decls = decls + f" = __riscv_vle32_v_i32m1(&{output.variable}, 1)"
            decls = decls + ";\n"
        return decls

    def input_decls(self, inputs):
        decls = ""
        for input in inputs:
            if not input.is_address():
                decls = decls + f"int {input.reg}_initial = {input.variable};\n"
                decls = decls + f"vint32m1_t {input.reg} = __riscv_vle32_v_i32m1(&{input.reg}_initial, 1);\n"
        return decls
    
    def asm_outputs(self, outputs):
        decls = ":"
        first = True
        for output in outputs:
            if first:
                first = False
            else:
                decls = decls + ", "
            constraint = output.constraint
            variable = output.variable
            if not output.is_address():
                constraint = constraint.replace('r', 'vr')
                variable = output.reg
            decls = decls + f"[{output.reg}] \"{constraint}\" ({variable})"
        return decls
    
    def output_final_reads(self, outputs):
        decls = ""
        for output in outputs:
            if not output.is_trashed():
                decls = decls + f"__riscv_vse32_v_i32m1(&{output.variable}, {output.reg}, 1);\n"
        return decls

    def process_register_declarations(self, asm_block):
        # Convert scalar register declarations to vector registers
        reg_pattern = r'(%\[x\d+\])\s+"r"\s+\('
        return re.sub(reg_pattern, r'v\1 "v" (', asm_block)

    def convert_scalar_to_vector(self, instruction):
        # Helper function to convert scalar instructions to vector equivalents
        instruction = re.sub(r'(%\[x\d+\]),', r'vmv.v.x v\1, ', instruction)
        instruction = re.sub(r',(%\[x\d+\])', r'vmv.x.s \1, ', instruction)
        return instruction

    def process_asm_block(self, asm_block):
        # Add vector initialization only at the start
        if "#START _litmus_" in asm_block:
            # Insert after the START marker
            parts = asm_block.split("#START _litmus_", 1)
            new_asm = parts[0] + "#START _litmus_" + parts[1]
            # Find the end of the START line
            start_end = new_asm.find('\n', new_asm.find("#START _litmus_")) + 1
            new_asm = new_asm[:start_end] + self.vector_init + new_asm[start_end:]
        else:
            # If no START marker, add at the beginning
            new_asm = self.vector_init + asm_block

        # Convert scalar instructions to vector instructions
        for pattern, replacement in self.conversions.items():
            new_asm = re.sub(pattern, replacement, new_asm)

        # Process each instruction
        lines = new_asm.split('\n')
        processed_lines = []
        for line in lines:
            processed_line = line
            #processed_line = self.convert_scalar_to_vector(line)
            processed_lines.append(processed_line)
        new_asm = '\n'.join(processed_lines)
        return new_asm

    def process_file(self, filepath):
        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Find all assembly block
            asm_pattern = r'asm\s+__volatile__\s*\(\s*"\\n"\s*(".*?")\s*:(.*?):(.*?):(.*?)\s*\);'

            modified_content = content
            
            modified_content = "#include <riscv_vector.h>\n" + modified_content
            
            # Process each assembly block
            for match in re.finditer(asm_pattern, content, re.DOTALL):
                statement = match.group(0)
                asm_block = match.group(1)
                outputs = match.group(2)
                inputs = match.group(3)
                clobbers = match.group(4)
                
                out_regs = self.parse_asm_outputs(outputs)
                in_regs = self.parse_asm_outputs(inputs)
                vectorized_asm = ""
                vectorized_asm = vectorized_asm + self.output_decls(out_regs)
                vectorized_asm = vectorized_asm + self.input_decls(in_regs)
                vectorized_asm = vectorized_asm + "asm __volatile__(\n"
                vectorized_asm = vectorized_asm + self.process_asm_block(asm_block) + "\n"
                vectorized_asm = vectorized_asm + self.asm_outputs(out_regs) + "\n"
                vectorized_asm = vectorized_asm + self.asm_outputs(in_regs) + "\n"
                vectorized_asm = vectorized_asm + ":" + clobbers + ", \"vl\", \"vtype\""
                vectorized_asm = vectorized_asm + ");\n"
                vectorized_asm = vectorized_asm + self.output_final_reads(out_regs) + "\n"
                modified_content = modified_content.replace(statement, vectorized_asm)

            # Write back to file
            with open(filepath, 'w') as f:
                f.write(modified_content)

            print(f"Successfully processed: {filepath}")
            return True

        except Exception as e:
            print(f"Error processing {filepath}: {str(e)}")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python vectorize_asm.py <directory or file>")
        sys.exit(1)

    target = sys.argv[1]
    vectorizer = AsmVectorizer()
    
    if os.path.isfile(target):
        vectorizer.process_file(target)
    else:
        for filepath in Path(target).rglob('*.c'):
            vectorizer.process_file(filepath)

if __name__ == "__main__":
    main()