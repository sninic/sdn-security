# zsh
ZSHRC="$HOME/.zshrc"
sudo apt install -y zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/zsh-users/zsh-completions ${ZSH_CUSTOM:=~/.oh-my-zsh/custom}/plugins/zsh-completions
sed -i '/^plugins=(git)/c\plugins=(\
    git\
    zsh-autosuggestions\
    zsh-syntax-highlighting\
    zsh-completions\
)' "$ZSHRC"
echo "" >> "$ZSHRC"
echo 'alias ll="ls -al"' >> "$ZSHRC"
source ~/.zshrc
